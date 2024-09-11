# SPDX-License-Identifier: MIT

import json
import logging
import socket
import struct
import threading
from ipaddress import IPv4Address, IPv4Network
from sys import stderr
from time import monotonic, sleep
from ..address_range import address_range
from .message import (Operation, HardwareType, Flags, MessageType, OptionMap,
	DHCP as DHCPMessage)
from .listener import (listen, DHCP_SERVER_PORT, DHCP_CLIENT_PORT)
from ..packet import (make_ipv4_pseudoheader, encapsulate_udp,
	encapsulate_ipv4, IPV4_FLAG_DONT_FRAGMENT, encapsulate_ethernet,
	IPV4_ETHERTYPE)
from .optiontypes import get as get_option, typelist
from ..platform_specific import (get_mask_from_iface, get_ip_from_iface,
	get_mac_from_iface, list_ifaces)
from .rfc2132 import RFC2132OptionType

from ..debug_helpers.pcap import PCAP, LinkLayer


class Error(Exception):
	pass


class IPInUseError(Error):
	pass


def get_client_id(packet):
	if not isinstance(packet, DHCPMessage):
		raise Exception('%r is not a DHCP packet' % packet)

	try:
		client_id = packet.options[RFC2132OptionType.CLIENT_IDENTIFIER]
	except Exception:
		client_id = bytes([packet.hardware_type, *packet.hardware_address])

	# preliminary notes: two different OSes on the same hardware will generally
	# share a client id, because client ids are based on hardware type and MAC,
	# and if the network card does not change, the hardware type and MAC do not
	# change; the DHCP specification does not specify this, but the behavior
	# seems to be the de facto standard
	return client_id


class BaseDHCPServer:
	def init_recv(self, interface):
		self.receive_socket = listen(interface + b'\0')
		self.receive_socket.settimeout(5)

	def init_send(self, interface):
		self.send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
		self.send_socket.bind((interface.decode('utf-8'), socket.IPPROTO_UDP))
		self.ip = get_ip_from_iface(interface)

	def __init__(self, logger, interface, pcap=None):
		self.housekeeping = []
		self.logger = logger
		try:
			interface = bytes(interface, 'utf-8')
		except TypeError:
			interface = bytes(interface)
		self.interface = interface
		self.pcap = pcap

		self.init_recv(interface)
		self.init_send(interface)

	def recv(self):
		data, addr = self.receive_socket.recvfrom(65535)

		# destination_mac = get_mac_from_iface(self.interface)
		destination_ip = IPv4Address(get_ip_from_iface(self.interface))
		destination_port = DHCP_SERVER_PORT
		# try:
		# 	source_mac = DHCPMessage.decode(data).hardware_address
		# except Exception:
		# 	source_mac = b'\xFE\xED\xFA\xCE\xBE\xEF'
		source_ip = IPv4Address(addr[0])
		source_port = addr[1]

		pseudoheader = make_ipv4_pseudoheader(
			source_ip,
			destination_ip,
			socket.IPPROTO_UDP,
			len(data) + 8
		)
		udp = encapsulate_udp(
			source_port,
			destination_port,
			data,
			pseudoheader=pseudoheader
		)
		ipv4 = encapsulate_ipv4(
			source_ip,
			destination_ip,
			socket.IPPROTO_UDP,
			udp,
			flags=IPV4_FLAG_DONT_FRAGMENT,
			time_to_live=16
		)
		if self.pcap is not None:
			self.pcap.add(ipv4)

		return data, addr

	def send(self, data, destination_mac, destination_ip='0.0.0.0'):
		# NOTE(tori): why must a simple DHCP server know how to encapsulate
		# all this stuff manually?
		# simply put, abstractions; that is, python gives us 0.0.0.0:68 when we
		# `recvfrom()`, which in C would be a `struct sockaddr_in`, which we
		# could simply reuse, apparently
		destination_ip = IPv4Address(destination_ip)
		source_mac = get_mac_from_iface(self.interface)
		source_ip = get_ip_from_iface(self.interface)
		source_port = DHCP_SERVER_PORT
		destination_port = DHCP_CLIENT_PORT

		pseudoheader = make_ipv4_pseudoheader(
			source_ip,
			destination_ip,
			socket.IPPROTO_UDP,
			len(data) + 8
		)
		udp = encapsulate_udp(
			source_port,
			destination_port,
			data,
			pseudoheader=pseudoheader
		)
		ipv4 = encapsulate_ipv4(
			source_ip,
			destination_ip,
			socket.IPPROTO_UDP,
			udp,
			flags=IPV4_FLAG_DONT_FRAGMENT,
			time_to_live=16
		)
		ethernet = encapsulate_ethernet(
			source_mac,
			destination_mac,
			IPV4_ETHERTYPE,
			ipv4
		)
		if self.pcap is not None:
			self.pcap.add(ipv4)
		self.send_socket.send(ethernet)

	def handle_client(self):
		try:
			data, address = self.recv()
			request_packet = DHCPMessage.decode(data)
			request_type = MessageType(request_packet.options[
				RFC2132OptionType.MESSAGE_TYPE])
		except socket.timeout:
			return
		except Exception as e:
			self.logger.error('could not decode packet (caused by %r)', e)
			return

		if not hasattr(self, 'do_%s' % request_type.name):
			self.logger.warning('not implemented: %s', request_type.name)
			return

		handler = getattr(self, 'do_%s' % request_type.name)

		try:
			response_packet = handler(request_packet)
		except Exception as e:
			response_packet = None
			self.logger.error('could not handle request (caused by %r)',
				type(e).__name__)
			if __debug__:
				raise e

		if response_packet is None:
			return

		response_type = MessageType(response_packet.options[
			RFC2132OptionType.MESSAGE_TYPE])

		client_id = get_client_id(request_packet)
		self.logger.info('%s - received %s, replying %s', client_id,
			request_type.name, response_type.name)

		destination_mac = (
			b'\xFF\xFF\xFF\xFF\xFF\xFF'
			if response_packet.flags & Flags.BROADCAST
			else response_packet.hardware_address
		)
		destination_ip = (
			b'\xFF\xFF\xFF\xFF'
			if response_packet.flags & Flags.BROADCAST
			else response_packet.your_ip
		)

		self.send(
			data=response_packet.encode(),
			destination_mac=destination_mac,
			destination_ip=destination_ip
		)

	def handle_housekeeping(self):
		for method in self.housekeeping:
			method()


class Server(BaseDHCPServer):
	def __init__(self, logger, interface, pool=None, options=None,
		set_default_options=True, get_options=None, pcap=None):
		super().__init__(logger, interface, pcap)

		ip = get_ip_from_iface(self.interface)
		mask = get_mask_from_iface(self.interface)
		network = IPv4Network((
			int(ip) & int(mask),
			str(mask)
		))
		broadcast = network.broadcast_address
		self.ip = ip

		self.logger.info(f'if = {self.interface}, ip = {ip}, mask = {mask}, '
			f'network = {network}, broadcast = {broadcast}')

		if pool is None:
			ip_is_first = (ip == network[1])
			ip_is_last = (ip == network[-2])
			if ip_is_first:
				pool_range = address_range(network[2], network[-2])
			elif ip_is_last:
				pool_range = address_range(network[1], network[-3])
			else:
				raise Exception(
					'cannot make a pool from configured ip and mask')
			pool = pool_range
		self.pool = pool

		server_options = {}
		if set_default_options:
			default_options = {
				RFC2132OptionType.SERVER_IDENTIFIER: ip,
				RFC2132OptionType.SUBNET_MASK: mask,
				RFC2132OptionType.ROUTER: (ip,),
				RFC2132OptionType.DOMAIN_NAME_SERVER: ('8.8.8.8', '8.8.4.4'),
				RFC2132OptionType.BROADCAST_ADDRESS: broadcast,
				RFC2132OptionType.IP_ADDRESS_LEASE_TIME: 3000,
				RFC2132OptionType.RENEWAL_TIME_VALUE: 1500,
				RFC2132OptionType.REBINDING_TIME_VALUE: 2000,
			}
			for option, value in default_options.items():
				server_options.setdefault(option, value)
		if options is not None:
			for option, value in options.items():
				server_options[option] = value
		self.options = server_options

		self.get_options = get_options

		self.unassigned = set(self.pool)
		self.saved = set()
		self.assigned = set()
		self.client_data = {}

		self.housekeeping.append(self.handle_expirations)

	def select_ip(self, client_data, preference=None):
		if preference in self.unassigned:
			return preference
		# NOTE(tori): if we have a saved address, give them that
		if (address := client_data.get('ip')) is not None:
			return address
		try:
			ip = self.unassigned.pop()
			self.unassigned.add(ip)
			return ip
		except KeyError:
			self.logger.info('could not get IP address')
			return None

	def address_sanity_check(self):
		# NOTE(tori): check that each address in pool appears only once in
		# either assigned or assigned
		assert set(self.pool) == (self.unassigned ^ self.assigned)

	def assign_ip(self, address):
		if address is None:
			raise Exception(address)
		self.address_sanity_check()
		address = IPv4Address(address)
		try:
			self.unassigned.remove(address)
			self.assigned.add(address)
		except KeyError:
			raise IPInUseError('address %r could not be assigned' % address)

	def release_ip(self, address):
		self.address_sanity_check()
		address = IPv4Address(address)
		try:
			self.assigned.remove(address)
			self.unassigned.add(address)
			return
		except KeyError:
			pass

	def get_client_data(self, client_id):
		client_data = self.client_data.setdefault(client_id, {
			'id': client_id,
			'ip': None
		})
		# NOTE(tori): set a timestamp so we can deal with client object
		# lifetimes
		client_data['last_update'] = monotonic()
		return client_data

	def make_response_packet(self, request, message_type):
		response = DHCPMessage(op=Operation.REPLY)
		response.hardware_type = HardwareType.ETH10MB
		response.transaction_id = request.transaction_id
		response.flags = request.flags
		response.gateway_ip = request.gateway_ip
		# TODO(tori): allow gateway function
		response.server_ip = self.ip
		response.hardware_address = request.hardware_address
		response.server_name = socket.gethostname().encode('utf-8')

		response.options[RFC2132OptionType.MESSAGE_TYPE] = message_type
		return response

	def add_server_options(self, request, response):
		# if the client didn't request any options, just send all known options
		requested_options = request.options.get(
			RFC2132OptionType.PARAMETER_REQUEST_LIST,
			self.options.keys()
		)
		unknown_options = []
		for option in requested_options:
			value = self.options.get(option)
			if value is None:
				unknown_options.append(option)
				continue
			response.options[option] = value

		self.logger.debug('unknown options: %s' % ', '.join(
			repr(get_option(option, ignore_unknown=True))
			for option
			in unknown_options
		))

	def handle_get_options(self, request, response):
		if self.get_options is None:
			return

		# NOTE(tori): here we allow for application code to provide options
		# by editing the response directly or by returning a dict of options
		# note that nothing stops the application code from modifying the
		# response in other ways, it's my way of allowing monkey-patching
		try:
			options = self.get_options(request, response)
		except TypeError:
			options = self.get_options(request)

		if options is None:
			return

		for option, value in options.items():
			response.options[option] = value

	def handle_rfc6842(self, request, response):
		if RFC2132OptionType.CLIENT_IDENTIFIER in request.options:
			response.options[RFC2132OptionType.CLIENT_IDENTIFIER] = (
				request.options[RFC2132OptionType.CLIENT_IDENTIFIER])
		else:
			try:
				del response.options[RFC2132OptionType.CLIENT_IDENTIFIER]
			except KeyError:
				pass

	def handle_option_requirements(self, request, response):
		req_message_type = request.options[RFC2132OptionType.MESSAGE_TYPE]
		res_message_type = response.options[RFC2132OptionType.MESSAGE_TYPE]

		required_options = ()
		optional_options = ()
		illegal_options = ()

		if res_message_type == MessageType.OFFER:
			required_options += (
				RFC2132OptionType.IP_ADDRESS_LEASE_TIME,
				RFC2132OptionType.MESSAGE_TYPE,
				RFC2132OptionType.SERVER_IDENTIFIER,
			)
			optional_options += (
				RFC2132OptionType.OPTION_OVERLOAD,
				RFC2132OptionType.MESSAGE,
				RFC2132OptionType.VENDOR_CLASS_IDENTIFIER,
			)
			illegal_options += (
				RFC2132OptionType.REQUESTED_IP_ADDRESS,
				RFC2132OptionType.PARAMETER_REQUEST_LIST,
				# NOTE(tori): illegal in rfc2131, determinant in rfc6482
				# RFC2132OptionType.CLIENT_IDENTIFIER,
				RFC2132OptionType.MAXIMUM_DHCP_MESSAGE_SIZE,
			)

			if RFC2132OptionType.CLIENT_IDENTIFIER in request.options:
				required_options += (RFC2132OptionType.CLIENT_IDENTIFIER,)
			else:
				illegal_options += (RFC2132OptionType.CLIENT_IDENTIFIER,)

			optional_options += tuple(
				set(typelist)
				- set(required_options)
				- set(optional_options)
				- set(illegal_options)
			)
		elif res_message_type == MessageType.ACK:
			if req_message_type == MessageType.INFORM:
				required_options += (
				)
				optional_options += (
				)
				illegal_options += (
					RFC2132OptionType.IP_ADDRESS_LEASE_TIME,
				)
			elif req_message_type == MessageType.REQUEST:
				required_options += (
					RFC2132OptionType.IP_ADDRESS_LEASE_TIME,
				)
				optional_options += (
				)
				illegal_options += (
				)
			else:
				raise Exception('unhandled code path')

			required_options += (
				RFC2132OptionType.MESSAGE_TYPE,
				RFC2132OptionType.SERVER_IDENTIFIER,
			)
			optional_options += (
				RFC2132OptionType.OPTION_OVERLOAD,
				RFC2132OptionType.MESSAGE,
			)
			illegal_options += (
				RFC2132OptionType.REQUESTED_IP_ADDRESS,
				RFC2132OptionType.PARAMETER_REQUEST_LIST,
				# RFC2132OptionType.CLIENT_IDENTIFIER,
				RFC2132OptionType.MAXIMUM_DHCP_MESSAGE_SIZE
			)

			if RFC2132OptionType.CLIENT_IDENTIFIER in request.options:
				required_options += (RFC2132OptionType.CLIENT_IDENTIFIER,)
			else:
				illegal_options += (RFC2132OptionType.CLIENT_IDENTIFIER,)

			optional_options += tuple(
				set(typelist)
				- set(required_options)
				- set(optional_options)
				- set(illegal_options)
			)
		elif res_message_type == MessageType.NAK:
			required_options += (
				RFC2132OptionType.MESSAGE_TYPE,
				RFC2132OptionType.SERVER_IDENTIFIER,
			)
			optional_options += (
				RFC2132OptionType.MESSAGE_TYPE,
				# NOTE(tori): client identifier is removed in rfc6482
				# RFC2132OptionType.CLIENT_IDENTIFIER,
				RFC2132OptionType.VENDOR_CLASS_IDENTIFIER,
			)
			illegal_options += (
				RFC2132OptionType.REQUESTED_IP_ADDRESS,
				RFC2132OptionType.IP_ADDRESS_LEASE_TIME,
				RFC2132OptionType.OPTION_OVERLOAD,
				RFC2132OptionType.PARAMETER_REQUEST_LIST,
				RFC2132OptionType.MAXIMUM_DHCP_MESSAGE_SIZE,
			)

			if RFC2132OptionType.CLIENT_IDENTIFIER in request.options:
				required_options += (RFC2132OptionType.CLIENT_IDENTIFIER,)
			else:
				illegal_options += (RFC2132OptionType.CLIENT_IDENTIFIER,)

			illegal_options += tuple(
				set(typelist)
				- set(required_options)
				- set(optional_options)
				- set(illegal_options)
			)
		else:
			raise Exception('unhandled code path')

		assert set(required_options).isdisjoint(set(optional_options))
		assert set(optional_options).isdisjoint(set(required_options))
		assert set(required_options).isdisjoint(set(illegal_options))

		for option in required_options:
			if option not in response.options:
				value = self.options.get(option)
				if value is None:
					raise Exception('required option not provided: %r'
						% option)
				response.options[option] = value

		for option in optional_options:
			pass

		for option in illegal_options:
			if option in response.options:
				self.logger.warning('illegal option in %r: %r'
					% (res_message_type, option))
				del response.options[option]

	def handle_options(self, request, response):
		self.add_server_options(request, response)
		self.handle_get_options(request, response)
		self.handle_rfc6842(request, response)
		self.handle_option_requirements(request, response)

	def do_DISCOVER(self, request):
		client_data = self.get_client_data(get_client_id(request))

		response = self.make_response_packet(request, MessageType.OFFER)

		ip = self.select_ip(client_data, request.options.get(
			RFC2132OptionType.REQUESTED_IP_ADDRESS))

		if ip is None:
			self.logger.warning('could not assign IP address')
			return None

		client_data['ip'] = ip
		response.your_ip = ip

		self.handle_options(request, response)

		return response

	def do_REQUEST(self, request):
		client_data = self.get_client_data(get_client_id(request))

		response = self.make_response_packet(request, MessageType.ACK)

		ip = client_data['ip']
		if ip is None:
			ip = self.select_ip(client_data, request.options.get(
				RFC2132OptionType.REQUESTED_IP_ADDRESS))
		if ip not in self.assigned:
			self.assign_ip(ip)

		response.your_ip = ip

		self.handle_options(request, response)

		return response

	def do_INFORM(self, request):
		# client_data = self.get_client_data(get_client_id(request))

		response = self.make_response_packet(request, MessageType.ACK)

		response.your_ip = request.client_ip

		self.handle_options(request, response)

		return response

	def do_DECLINE(self, request):
		client_data = self.get_client_data(get_client_id(request))
		client_data['last_update'] = -(2 ** 31)

		self.release_ip(request.options.get(
			RFC2132OptionType.REQUESTED_IP_ADDRESS))

	def do_RELEASE(self, request):
		client_data = self.get_client_data(get_client_id(request))
		client_data['last_update'] = -(2 ** 31)

		self.release_ip(request.options.get(
			RFC2132OptionType.REQUESTED_IP_ADDRESS))

	def handle_expirations(self):
		now = monotonic()
		lease_duration = self.options[RFC2132OptionType.IP_ADDRESS_LEASE_TIME]
		to_remove = []
		for client_id, client_data in self.client_data.items():
			client_age = now - client_data['last_update']
			if client_age > lease_duration*2:
				to_remove.append(client_id)

		for client_id in to_remove:
			self.logger.debug('%s - lease expired' % client_id)
			del self.client_data[client_id]


# TODO(tori): implement
class RelayAgent(BaseDHCPServer):
	def __init__(self, logger, interface, server):
		super().__init__(logger, interface)
		self.server = server
		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
			1)
		self.server_socket.bind(('0.0.0.0', DHCP_CLIENT_PORT))


def configure_logging(output='-', level='INFO'):
	if isinstance(output, str):
		if output == '-':
			logging.basicConfig(stream=stderr)
		else:
			logging.basicConfig(filename=output)
	else:
		logging.basicConfig(stream=output)

	log_format = '{asctime}|{name}|{levelname}|{message}'
	log_formatter = logging.Formatter(log_format, style='{')

	log_handler = logging.StreamHandler()
	log_handler.setFormatter(log_formatter)

	logger = logging.Logger(__name__)
	logger.addHandler(log_handler)

	logger.setLevel(level)

	return logger


class DHCPDaemon:
	def client_target(self):
		while self.running:
			self.server.handle_client()
			sleep(1)

	def housekeeping_target(self):
		while self.running:
			self.server.handle_housekeeping()
			sleep(10)

	def __init__(self, *args, **kwargs):
		self.server = Server(*args, **kwargs)
		self.running = False
		self.client_thread = None
		self.housekeeping_thread = None

	def run(self):
		if self.running:
			return False
		self.running = True
		self.client_thread = threading.Thread(target=self.client_target)
		self.housekeeping_thread = threading.Thread(target=self.housekeeping_target)
		self.client_thread.start()
		self.housekeeping_thread.start()
		return True

	def stop(self):
		if not self.running:
			return False
		self.running = False
		self.client_thread.join()
		self.housekeeping_thread.join()
		return True


def main():
	import argparse

	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--log-file', default='-',
		type=argparse.FileType('w'), help='location to log messages')
	parser.add_argument('-l', '--log-level', default='INFO', choices=('ALL',
		'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'), type=str.upper,
		help='verbosity of log messages, in descending order')
	parser.add_argument('interface', metavar='IF', default='lo',
		choices=list_ifaces(),
		help='interface on which to bind: one of %(choices)s')
	args = parser.parse_args()

	target = args.log_file
	level = 0 if args.log_level == 'ALL' else getattr(logging, args.log_level)
	logger = configure_logging(output=target, level=level)

	try:
		pcap = PCAP(link_layer=LinkLayer.RAW_IPV4)
		server = Server(logger, args.interface,
			pool=address_range('10.0.0.2', '10.0.0.254'), pcap=pcap)
		while True:
			try:
				server.handle_housekeeping()
				server.handle_client()
			except KeyboardInterrupt:
				with open('log.pcap', 'wb') as pcap_log:
					pcap_log.write(pcap.encode())
				break
	except Exception as e:
		logger.error('unhandled server error (caused by %r)', e)
		if __debug__:
			raise e


if __name__ == '__main__':
	main()

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
