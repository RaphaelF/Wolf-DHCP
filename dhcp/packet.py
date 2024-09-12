# SPDX-License-Identifier: MIT

import struct
from binascii import crc32
from ipaddress import IPv4Address, IPv6Address
from random import randrange


def calculate_internet_checksum(packet):
	"""Calculate checksum of data as defined in RFC791."""
	if len(packet)%2:
		packet += b'\x00'

	checksum = 0
	for i in range(0, len(packet) & ~1, 2):
		msb, lsb = packet[i:i + 2]
		checksum += msb << 8 | lsb
		checksum = (checksum & 0xFFFF) + (checksum >> 16)
	return ~checksum & 0xFFFF


# NOTE(tori): only generate checksum if absolutely necessary, it seems the
# driver will automatically generate one if one is not passed, according to SO
# https://stackoverflow.com/questions/1117958/how-do-i-use-raw-socket-in-python#comment22219164_6374862
IPV4_ETHERTYPE = 0x0800
IPV6_ETHERTYPE = 0x86DD


def encapsulate_ethernet(source, destination, ethertype, data, tag=None,
	generate_checksum=False):
	"""Wrap data in ethernet frame information."""
	destination = bytes(destination)
	if len(destination) != 6:
		raise Exception('bad destination: %r' % destination)
	source = bytes(source)
	if len(source) != 6:
		raise Exception('bad source: %r' % source)

	try:
		ethertype = struct.pack('!H', ethertype)
	except Exception:
		ethertype = bytes(ethertype)
	if len(ethertype) != 2:
		raise Exception('bad ethertype: %r' % ethertype)

	if tag is None:
		header = struct.pack('!6s6s2s', destination, source, ethertype)
	else:
		if len(tag) != 4:
			raise Exception('bad tag: %r' % tag)
		header = struct.pack('!6s6s4s2s', destination, source, tag, ethertype)

	if generate_checksum:
		# NOTE(tori): the little endian is intentional
		frame_check_sequence = struct.pack('<I',
			crc32(header + data) & 0xFFFFFFFF)
	else:
		frame_check_sequence = b''

	frame = header + data + frame_check_sequence

	return frame


IPV4_FLAG_RESERVED = 0x04
IPV4_FLAG_EVIL = 0x04
IPV4_FLAG_DONT_FRAGMENT = 0x02
IPV4_FLAG_MORE_FRAGMENTS = 0x01


def encapsulate_ipv4(source, destination, protocol, data, *,
	differentiated_services_code_point=0, explicit_congestion_notification=0,
	identification=None, flags=0, fragment_offset=0, time_to_live=64,
	options=b''):
	source = IPv4Address(source)
	destination = IPv4Address(destination)
	data = bytes(data)

	if differentiated_services_code_point not in range(1 << 6):
		raise Exception('bad DSCP: %r' % differentiated_services_code_point)

	if explicit_congestion_notification not in range(1 << 2):
		raise Exception('bad ECN: %r' % explicit_congestion_notification)

	if identification is None:
		identification = randrange(1 << 16)
	if identification not in range(1 << 16):
		raise Exception('bad identification: %r' % identification)

	if flags not in range(1 << 3):
		raise Exception('bad flags: %r' % flags)

	if fragment_offset not in range(1 << 13):
		raise Exception('bad fragment offset: %r' % fragment_offset)

	if time_to_live not in range(1 << 8):
		raise Exception('bad TTL: %r' % time_to_live)

	if protocol not in range(1 << 8):
		raise Exception('bad protocol: %r' % protocol)

	if len(options)/4 not in range(11):
		raise Exception('bad options: %r' % options)

	version = 0x04
	header_length = int(5 + len(options)/4)
	total_length = header_length*4 + len(data)

	header_checksum = 0
	header = (struct.pack('!BBHHHBBH4s4s', (version << 4) | header_length,
		(differentiated_services_code_point << 2)
		| explicit_congestion_notification, total_length, identification,
		(flags << 13) | fragment_offset, time_to_live, protocol,
		header_checksum, source.packed, destination.packed) + options)
	header_checksum = calculate_internet_checksum(header)
	header = (struct.pack('!BBHHHBBH4s4s', (version << 4) | header_length,
		(differentiated_services_code_point << 2)
		| explicit_congestion_notification, total_length, identification,
		(flags << 13) | fragment_offset, time_to_live, protocol,
		header_checksum, source.packed, destination.packed) + options)

	return header + data


def encapsulate_ipv6(source, destination, next_header, data, *,
	differentiated_services_field=0, explicit_congestion_notification=0,
	payload_length=None, flow_label=None, hop_limit=64):
	source = IPv6Address(source)
	destination = IPv6Address(destination)
	data = bytes(data)

	if differentiated_services_field not in range(1 << 6):
		raise Exception('bad DSCP: %r' % differentiated_services_field)
	differentiated_services_field <<= 2

	if explicit_congestion_notification not in range(1 << 2):
		raise Exception('bad ECN: %r' % explicit_congestion_notification)

	if flow_label is None:
		flow_label = randrange(1 << 20)
	if flow_label not in range(1 << 20):
		raise Exception('bad flow label: %r' % flow_label)

	if payload_length is None:
		payload_length = len(data)
	if payload_length not in range(1 << 16):
		raise Exception('bad payload length (too large?): %r' % payload_length)

	if next_header not in range(1 << 8):
		raise Exception('bad "Next Header" value: %r' % next_header)

	if hop_limit not in range(1 << 8):
		raise Exception('bad hop limit: %r' % hop_limit)

	version = 6

	header = struct.pack('!IHBB16s16s', (version << 28)
		| (differentiated_services_field << 22)
		| (explicit_congestion_notification << 20) | flow_label,
		payload_length, next_header, hop_limit, source.packed,
		destination.packed)

	return header + data


def make_ipv4_pseudoheader(source, destination, protocol, data_length):
	source = IPv4Address(source)
	destination = IPv4Address(destination)

	if protocol not in range(1 << 8):
		raise Exception('bad protocol: %r' % protocol)

	return struct.pack('!4s4sxBH', source.packed, destination.packed, protocol,
		data_length)


def make_ipv6_pseudoheader(source, destination, next_header, data_length):
	source = IPv6Address(source)
	destination = IPv6Address(destination)

	if next_header not in range(1 << 8):
		raise Exception('bad "Next Header" value: %r' % next_header)

	return struct.pack('!16s16sII', source.packed, destination.packed,
		data_length, next_header)


def encapsulate_udp(source, destination, data, *, pseudoheader=None):
	if source not in range(1 << 16):
		raise Exception('bad source: %r' % source)

	if destination not in range(1 << 16):
		raise Exception('bad destination: %r' % destination)

	if not isinstance(data, bytes):
		raise Exception('bad data: %r' % data)

	checksum = 0
	if pseudoheader is not None:
		udp_header = struct.pack('!HHHH', source, destination, len(data) + 8,
			checksum)
		checksum = calculate_internet_checksum(pseudoheader + udp_header
			+ data)

	udp_header = struct.pack('!HHHH', source, destination, len(data) + 8,
		checksum)

	return udp_header + data

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
