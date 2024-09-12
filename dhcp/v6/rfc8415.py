# SPDX-License-Identifier: MIT

__all__ = ['RFC8415OptionType', 'rfc8415_option_codec']

import enum
import struct
from uuid import UUID

from .optiontypes import register as register_optiontype
from .option_codecs import register as register_optioncodec, Codec


class RFC8415OptionType(enum.IntEnum):
	CLIENTID = 1
	SERVERID = 2
	IA_NA = 3
	IA_TA = 4
	IAADDR = 5
	ORO = 6
	PREFERENCE = 7
	ELAPSED_TIME = 8
	RELAY_MSG = 9
	AUTH = 11
	UNICAST = 12
	STATUS_CODE = 13
	RAPID_COMMIT = 14
	USER_CLASS = 15
	VENDOR_CLASS = 16
	VENDOR_OPTS = 17
	INTERFACE_ID = 18
	RECONF_MSG = 19
	RECONF_ACCEPT = 20
	IA_PD = 25
	IAPREFIX = 26
	INFORMATION_REFRESH_TIME = 32
	SOL_MAX_RT = 82
	INF_MAX_RT = 83


class DUID:
	DUID_TYPE = None
	DUID_TYPES = {}

	def __init_subclass__(cls, /, duid_type):
		cls.__bases__[0].DUID_TYPES[duid_type] = cls

	@classmethod
	def decode(cls, duid):
		duid_type, = struct.unpack_from('!H', duid)
		return cls.DUID_TYPES[duid_type].decode(duid)


class DUID_LLT(DUID, duid_type=1):
	STRUCT = struct.Struct('!HHI')

	def __init__(self, hardware_type, time, link_layer_address):
		self.hardware_type = hardware_type
		self.time = time
		self.link_layer_address = link_layer_address

	def encode(self):
		return (self.STRUCT.pack(1, self.hardware_type, self.time)
			+ self.link_layer_address)

	@classmethod
	def decode(cls, duid):
		duid_type, hardware_type, time = cls.STRUCT.unpack_from(duid)
		link_layer_address = duid[cls.STRUCT.size:]
		self = cls(hardware_type, time, link_layer_address)
		return self


class DUID_EN(DUID, duid_type=2):
	STRUCT = struct.Struct('!HI')

	def __init__(self, enterprise_number, identifier):
		self.enterprise_number = enterprise_number
		self.identifier = identifier

	def encode(self):
		return self.STRUCT.pack(2, self.enterprise_number) + self.identifier

	@classmethod
	def decode(cls, duid):
		duid_type, enterprise_number = cls.STRUCT.unpack_from(duid)
		identifier = duid[cls.STRUCT.size:]
		self = cls(enterprise_number, identifier)
		return self


class DUID_LL(DUID, duid_type=3):
	STRUCT = struct.Struct('!HH')

	def __init__(self, hardware_type, link_layer_address):
		self.hardware_type = hardware_type
		self.link_layer_address = link_layer_address

	def encode(self):
		return (self.STRUCT.pack(3, self.hardware_type)
			+ self.link_layer_address)

	@classmethod
	def decode(cls, duid):
		duid_type, hardware_type = cls.STRUCT.unpack_from(duid)
		link_layer_address = duid[cls.STRUCT.size:]
		self = cls(hardware_type, link_layer_address)
		return self


class DUID_UUID(DUID, duid_type=4):
	STRUCT = struct.Struct('!H16s')

	def __init__(self, uuid):
		self.uuid = UUID(uuid)

	def encode(self):
		return self.STRUCT.pack(4, self.uuid.bytes)

	@classmethod
	def decode(cls, duid):
		duid_type, uuid = cls.STRUCT.unpack_from(duid)
		self = cls(uuid)
		return self


def encode_duid(decoded):
	if not isinstance(decoded, DUID):
		raise Exception('%r is not a DUID' % decoded)
	return decoded.encode()


def decode_duid(encoded):
	return DUID.decode(encoded)


rfc8415_option_codec = Codec(
	name='rfc8415',
	codecs={
		RFC8415OptionType.CLIENTID: (
			encode_duid,
			decode_duid
		),
	}
)

register_optiontype(RFC8415OptionType)
register_optioncodec(rfc8415_option_codec)

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
