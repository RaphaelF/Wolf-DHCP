# SPDX-License-Identifier: MIT

from enum import Enum, IntEnum
from time import time_ns

from .namedstruct import NamedStruct, unpack_from

VERSION = (2, 4)


class Endian(Enum):
	NATIVE = '@'
	BIG = '>'
	LITTLE = '<'


class LinkLayer(IntEnum):
	IEEE_802_3 = 0x00000001
	ETHERNET = IEEE_802_3
	RAW_IP = 0x00000065
	IEEE_802_11 = 0x00000069
	WIFI = IEEE_802_11
	IEEE_802_15_4 = 0x000000C3
	ZIGBEE = IEEE_802_15_4
	RAW_IPV4 = 0x000000E4
	RAW_IPV6 = 0x000000E5


HEADER_FMT = ('%s{magic!I}{version_major!H}{version_minor!H}{timezone!I}'
	'{accuracy!I}{max_packet!I}{link_layer!I}')
PACKET_FMT = ('%s{seconds!I}{microseconds!I}{captured_length!I}'
	'{original_length!I}')

# NOTE(tori): pcap format
# https://www.netresec.com/?page=Blog&month=2022-10&post=What-is-a-PCAP-file


class Packet:
	def __init__(self, data, timestamp=None):
		self.data = data

		if timestamp is None:
			timestamp = time_ns()
		self.timestamp = timestamp

	def __repr__(self):
		if len(self.data) > 20:
			data_window = self.data[:16] + b'...'
		else:
			data_window = self.data
		return '%s(%r)' % (type(self).__name__, data_window)


class PCAP:
	def __init__(self, *, link_layer, max_packet=0x0400, endian=None,
		timezone=0, accuracy=0):
		self.link_layer = link_layer
		self.max_packet = max_packet

		if endian is None:
			endian = Endian.BIG
		else:
			endian = Endian(endian)
		self.endian = endian

		self.timezone = timezone
		self.accuracy = accuracy

		self.header_struct = NamedStruct(HEADER_FMT
			% self.endian.value, 'PCAPHeader')
		self.packet_struct = NamedStruct(PACKET_FMT
			% self.endian.value, 'PacketHeader')
		self.packets = []

	def add(self, data, timestamp=None):
		packet = Packet(data, timestamp)
		self.packets.append(packet)

	def encode(self):
		header = self.header_struct.pack(
			magic=0xA1B2C3D4,
			version_major=VERSION[0],
			version_minor=VERSION[1],
			timezone=self.timezone,
			accuracy=self.accuracy,
			max_packet=self.max_packet,
			link_layer=self.link_layer
		)
		packets = [
			self.packet_struct.pack(
				seconds=int(packet.timestamp//1000000000),
				microseconds=int((packet.timestamp//1000)%1000000),
				captured_length=min(self.max_packet, len(packet.data)),
				original_length=len(packet.data)
			) + packet.data[:self.max_packet]
			for packet
			in self.packets
		]
		return header + b''.join(packets)

	@classmethod
	def decode(cls, data):
		unpack = unpack_from('>{magic!I}', data)
		if unpack.magic == 0xA1B2C3D4:
			# big endian, epoch time
			endian = Endian.BIG
		elif unpack.magic == 0xD4C3B2A1:
			# little endian, epoch time
			endian = Endian.LITTLE
		else:
			raise Exception('bad magic value: %s', hex(unpack.magic))

		named_data = unpack_from(HEADER_FMT % endian.value, data)

		self = cls(link_layer=named_data.link_layer,
			max_packet=named_data.max_packet, endian=endian,
			timezone=named_data.timezone, accuracy=named_data.accuracy)

		offset = self.header_struct.size
		while offset < len(data):
			packet_header = self.packet_struct.unpack_from(data, offset)
			offset += self.packet_struct.size

			nanoseconds = (0
				+ packet_header.seconds * 1000000000
				+ packet_header.microseconds * 1000)
			packet_data = data[offset:offset + packet_header.captured_length]
			self.packets.append(Packet(packet_data, nanoseconds))

			offset += packet_header.captured_length
		return self

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
