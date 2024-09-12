#!/usr/bin/env python3
"""PXE

PXE launcher for dhcp server

"""

import logging
import threading
from time import sleep

from . import tftp as tftp
from .v4 import server as dhcp_server, rfc4578, rfc2132, rfc3004
from .debug_helpers.pcap import PCAP, LinkLayer

__all__ = ['main']
__author__ = 'Tori Wolf <wiredwolf@wiredwolf.gg>'
__date__ = '2023-08-27'
# SPDX tag
# SPDX-License-Identifier: MIT
__license__ = 'MIT'
__copyright__ = '2023 Tori Wolf'


def make_option_getter(mapping, ip):
	if mapping is None:
		return None

	pairs = [pair.split(':') for pair in mapping.split(',')]
	arch_to_boot = {int(pair[0]): pair[1] for pair in pairs}

	def get_options(request):
		user_client_identifier = request.options.get(
			rfc3004.RFC3004OptionType.USER_CLASS_IDENTIFIER, None)
		if user_client_identifier == b'iPXE':
			return {
				rfc2132.RFC2132OptionType.TFTP_SERVER_NAME: str(ip),
				rfc2132.RFC2132OptionType.BOOTFILE_NAME: 'script.ipxe'
			}

		arches = request.options.get(
			rfc4578.RFC4578OptionType.CLIENT_SYSTEM_ARCHITECTURE_TYPE, None)
		if arches is None:
			return

		for arch in arches:
			image = arch_to_boot.get(arch, None)
			if image is not None:
				break

		if image is None:
			return

		return {
			rfc2132.RFC2132OptionType.TFTP_SERVER_NAME: str(ip),
			rfc2132.RFC2132OptionType.BOOTFILE_NAME: image
		}

	return get_options


def tftp_server_target(logger, ip, root, state):
	logger.info('tftp server starting')
	server = tftp.Server(logger, tftp.folder_manager(root), ip)
	while state['running']:
		server.accept()
	server.wait_until_finished()


def dhcp_server_target(logger, interface, options, get_options, capture_file,
	state):
	logger.info('dhcp server starting')
	pcap = PCAP(link_layer=LinkLayer.RAW_IPV4)
	server = dhcp_server.Server(logger, interface, options=options,
		set_default_options=True, get_options=get_options, pcap=pcap)
	while state['running']:
		server.handle_expirations()
		server.handle_client()
	if capture_file is not None:
		with open(capture_file, 'wb') as pcap_file:
			pcap_file.write(pcap.encode())


def main():
	import argparse
	from textwrap import dedent

	parser = argparse.ArgumentParser()
	parser.add_argument('-tf', '--tftp-log-file', default='-',
		type=argparse.FileType('w'), help='location to log tftp messages')
	parser.add_argument('-tl', '--tftp-log-level', default='INFO',
		choices=('ALL', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'),
		type=str.upper,
		help='verbosity of log messages for tftp server, in descending order')
	parser.add_argument('-df', '--dhcp-log-file', default='-',
		type=argparse.FileType('w'), help='location to log dhcp messages')
	parser.add_argument('-dl', '--dhcp-log-level', default='INFO',
		choices=('ALL', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'),
		type=str.upper,
		help='verbosity of log messages for dhcp server, in descending order')
	parser.add_argument('-r', '--tftp-root', metavar='ROOT',
		default='./tftpboot', help='directory out of which to serve files')
	parser.add_argument('-b', '--boot-file', metavar='BOOT',
		default='pxelinux.0', help='boot file name for PXE')
	map_example = dedent("""\
	0:tftpboot/bios/pxelinux.0,7:tftpboot/efi64/syslinux.efi
	These values are specified as their values defined for DHCP option 93, and
	so the server would send `tftpboot/bios/pxelinux.0` to non-UEFI x86 clients
	and `tftpboot/efi64/syslinux.efi` to UEFI x86-64 clients. (see RFC4578)
	""")
	parser.add_argument('-m', '--boot-file-map', metavar='MAP', default=None,
		help='map of machine types to boot file names, e.g. %s' % map_example)
	parser.add_argument('-p', '--root-path', metavar='ROOTPATH',
		default=None, help='root path option for DHCP')
	parser.add_argument('-c', '--capture-file', metavar='PCAP',
		default=None, help='pcap file in which to log DHCP packets')
	parser.add_argument('dhcp_interface', metavar='IF', default='lo',
		choices=dhcp_server.list_ifaces(),
		help='interface on which to bind: one of %(choices)s')
	args = parser.parse_args()

	server_ip = dhcp_server.get_ip_from_iface(args.dhcp_interface.encode('utf-8'))
	options = {
		rfc2132.RFC2132OptionType.TFTP_SERVER_NAME: str(server_ip),
		rfc2132.RFC2132OptionType.BOOTFILE_NAME: args.boot_file
	}

	if args.root_path is not None:
		options[rfc2132.RFC2132OptionType.ROOT_PATH] = args.root_path

	state = {'running': True}

	tftp_target = args.tftp_log_file
	tftp_level = (
		0
		if args.tftp_log_level == 'ALL'
		else getattr(logging, args.tftp_log_level)
	)
	tftp_logger = tftp.configure_logging(output=tftp_target, level=tftp_level)
	tftp_thread = threading.Thread(target=tftp_server_target, kwargs={
		'logger': tftp_logger,
		'ip': server_ip,
		'root': args.tftp_root,
		'state': state
	})

	dhcp_target = args.dhcp_log_file
	dhcp_level = (
		0
		if args.dhcp_log_level == 'ALL'
		else getattr(logging, args.dhcp_log_level)
	)
	dhcp_logger = dhcp_server.configure_logging(output=dhcp_target,
		level=dhcp_level)
	dhcp_thread = threading.Thread(target=dhcp_server_target, kwargs={
		'logger': dhcp_logger,
		'interface': args.dhcp_interface,
		'options': options,
		'get_options': make_option_getter(args.boot_file_map, server_ip),
		'capture_file': args.capture_file,
		'state': state
	})

	tftp_thread.start()
	dhcp_thread.start()

	while True:
		try:
			sleep(3600)
		except KeyboardInterrupt:
			print('shutting down...')
			state['running'] = False
			break


if __name__ == '__main__':
	main()

# vim:set ft=python ts=4 sw=4 noet ai cc=80:
