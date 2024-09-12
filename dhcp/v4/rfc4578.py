# SPDX-License-Identifier: MIT

__all__ = [
	# NOTE(tori): meat and potatoes of the module
	'RFC4578OptionType', 'rfc4578_option_codec',
	# NOTE(tori): other useful stuff
	'ArchitectureType', 'NetworkInterfaceType', 'MachineIdentifierType'
]

import enum
import struct
import uuid

from .optiontypes import register as register_optiontype
from .option_codecs import register as register_optioncodec, Codec


class RFC4578OptionType(enum.IntEnum):
	CLIENT_SYSTEM_ARCHITECTURE_TYPE = 93
	CLIENT_NETWORK_INTERFACE_IDENTIFIER = 94
	CLIENT_MACHINE_IDENTIFIER = 97
	PXE_RESERVED_128 = 128
	PXE_RESERVED_129 = 129
	PXE_RESERVED_130 = 130
	PXE_RESERVED_131 = 131
	PXE_RESERVED_132 = 132
	PXE_RESERVED_133 = 133
	PXE_RESERVED_134 = 134
	PXE_RESERVED_135 = 135


class ArchitectureType(enum.IntEnum):
	INTEL_X86PC = 0
	NEC_PC98 = 1
	EFI_ITANIUM = 2
	DEC_ALPHA = 3
	ARC_X86 = 4
	INTEL_LEAN_CLIENT = 5
	EFI_IA32 = 6
	EFI_X86_64 = 7
	EFI_XSCALE = 8
	EFI_BC = 9


def encode_client_system_architecture_type(decoded):
	try:
		types = tuple(decoded)
	except TypeError:
		types = (decoded,)
	encoded = b''.join(struct.pack('!H', type_) for type_ in types)
	if len(encoded) == 0:
		raise ValueError('no client system architectures defined')
	return encoded


def decode_client_system_architecture_type(encoded):
	if len(encoded) == 0:
		raise ValueError('no client system architectures defined')
	types = zip(*[iter(encoded)]*2, strict=True)
	types = (struct.unpack('!H', bytes(type_))[0] for type_ in types)
	decoded = []
	for type_ in types:
		try:
			type_ = ArchitectureType(type_)
		except ValueError:
			pass
		decoded.append(type_)
	decoded = tuple(decoded)
	return decoded


class NetworkInterfaceType(enum.IntEnum):
	UNIVERSAL_NETWORK_DEVICE_IDENTIFIER = 1
	UNDI = 1


def encode_client_network_interface_identifier(decoded):
	type_, major, minor = decoded
	type_ = NetworkInterfaceType(type_)
	encoded = struct.pack('!BBB', type_, major, minor)
	return encoded


def decode_client_network_interface_identifier(encoded):
	type_, major, minor = struct.unpack('!BBB', encoded)
	decoded = (NetworkInterfaceType(type_), major, minor)
	return decoded


class MachineIdentifierType(enum.IntEnum):
	GLOBALLY_UNIQUE_IDENTIFIER = 0
	GUID = 0


def encode_client_machine_identifier(decoded):
	type_, data = decoded
	type_ = MachineIdentifierType(type_)

	if type_ == MachineIdentifierType.GUID:
		if isinstance(data, uuid.UUID):
			data = data.bytes
		if len(data) != 16:
			raise ValueError('invalid UUID: %r' % data)
		encoded = struct.pack('!B16s', type_, data)
	else:
		raise ValueError('unhandled machine identifier type: %r' % type_)

	return encoded


def decode_client_machine_identifier(encoded):
	type_, = struct.unpack_from('!B', encoded)
	data = encoded[1:]

	type_ = MachineIdentifierType(type_)

	if type_ == MachineIdentifierType.GUID:
		data = uuid.UUID(bytes=data)
		decoded = (type_, data)
	else:
		raise ValueError('unhandled machine identifier type: %r' % type_)

	return decoded


rfc4578_option_codec = Codec(
	name='rfc4578',
	codecs={
		RFC4578OptionType.CLIENT_SYSTEM_ARCHITECTURE_TYPE: (
			encode_client_system_architecture_type,
			decode_client_system_architecture_type
		),
		RFC4578OptionType.CLIENT_NETWORK_INTERFACE_IDENTIFIER: (
			encode_client_network_interface_identifier,
			decode_client_network_interface_identifier
		),
		RFC4578OptionType.CLIENT_MACHINE_IDENTIFIER: (
			encode_client_machine_identifier,
			decode_client_machine_identifier
		),
		RFC4578OptionType.PXE_RESERVED_128: (lambda d: d, lambda d: d),
		RFC4578OptionType.PXE_RESERVED_129: (lambda d: d, lambda d: d),
		RFC4578OptionType.PXE_RESERVED_130: (lambda d: d, lambda d: d),
		RFC4578OptionType.PXE_RESERVED_131: (lambda d: d, lambda d: d),
		RFC4578OptionType.PXE_RESERVED_132: (lambda d: d, lambda d: d),
		RFC4578OptionType.PXE_RESERVED_133: (lambda d: d, lambda d: d),
		RFC4578OptionType.PXE_RESERVED_134: (lambda d: d, lambda d: d),
		RFC4578OptionType.PXE_RESERVED_135: (lambda d: d, lambda d: d),
	}
)

register_optiontype(RFC4578OptionType)
register_optioncodec(rfc4578_option_codec)

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
