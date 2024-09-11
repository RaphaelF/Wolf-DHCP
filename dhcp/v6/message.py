# SPDX-License-Identifier: MIT

import enum
import struct

from .rfc8415 import RFC8415OptionType, rfc8415_option_codec
from .optiontypes import get as get_option
from .option_codecs import encode as encode_option, decode as decode_option

__all__ = ['DHCP']


@enum.unique
class MessageType(enum.IntEnum):
	SOLICIT = 1
	ADVERTISE = 2
	REQUEST = 3
	CONFIRM = 4
	RENEW = 5
	REBIND = 6
	REPLY = 7
	RELEASE = 8
	DECLINE = 9
	RECONFIGURE = 10
	INFORMATION_REQUEST = 11
	RELAY_FORW = 12
	RELAY_REPL = 13


class OptionMap:
	OPTION_STRUCT = struct.Struct('!HH')

	@staticmethod
	def check_options(options):
		if options is None:
			options = {}
		elif isinstance(options, OptionMap):
			options = {**options._options}
		elif isinstance(options, dict):
			options = {**options}
		elif isinstance(options, list):
			opts = options
			options = {}
			for tag, value in opts:
				if tag not in options:
					options[tag] = value
				else:
					options[tag] += value
		else:
			raise TypeError('not supported: %r' % options)

		return options

	def __init__(self, values=None):
		self._options = self.check_options(values)

	def __getitem__(self, key):
		key = get_option(key, ignore_unknown=True)
		return decode_option(key, self._options.__getitem__(key),
			ignore_unknown=True)

	def __setitem__(self, key, value):
		key = get_option(key, ignore_unknown=True)
		self._options.__setitem__(key, encode_option(key, value,
			ignore_unknown=True))

	def __delitem__(self, key):
		key = get_option(key, ignore_unknown=True)
		self._options.__delitem__(key)

	def __contains__(self, key):
		key = get_option(key, ignore_unknown=True)
		return self._options.__contains__(key)

	def __iter__(self):
		return iter(self._options)

	def keys(self):
		return self._options.keys()

	def values(self):
		return self._options.values()

	def items(self):
		return self._options.items()

	def __repr__(self):
		return '%s(%r)' % (type(self).__name__, self._options)

	def get(self, key, default=None):
		key = get_option(key, ignore_unknown=True)
		value = self._options.get(key)
		if value is None:
			return default
		return decode_option(key, value, ignore_unknown=True)

	def encode(self):
		option_bytes = b''
		for option_type, option_value in self._options.items():
			option_length = len(option_value)
			option_bytes += self.OPTION_STRUCT.pack(option_type, option_length)
			option_bytes += option_value
		return option_bytes

	@classmethod
	def decode(cls, option_bytes):
		rest = option_bytes
		options = {}
		while rest:
			option_type, option_length = cls.OPTION_STRUCT.unpack_from(rest)
			option_type = get_option(option_type, ignore_unknown=True)
			rest = rest[cls.OPTION_STRUCT.size:]
			option_value, rest = rest[:option_length], rest[option_length:]
			if option_value not in options:
				options[option_type] = b''
			options[option_type] += option_value
		return cls(options)

	def asdict(self):
		return {**self._options}


class DHCP:
	MSG_TYPE_STRUCT = struct.Struct('!B')
	CLIENT_SERVER_STRUCT = struct.Struct('!B3s')
	RELAY_AGENT_SERVER_STRUCT = struct.Struct('!BB16s16s')

	def __init__(self, *, message_type, transaction_id=None, hop_count=None,
		link_address=None, peer_address=None, options=None):
		self.message_type = message_type
		self.transaction_id = transaction_id
		self.hop_count = hop_count
		self.link_address = link_address
		self.peer_address = peer_address
		self.options = options

	def __repr__(self):
		if self.message_type in (MessageType.RELAY_FORW,
			MessageType.RELAY_REPL):
			parts = [
				'message_type={message_type}'.format(
					message_type=self.message_type),
				'hop_count={hop_count}'.format(hop_count=self.hop_count),
				'link_address={link_address}'.format(
					link_address=self.link_address),
				'peer_address={peer_address}'.format(
					peer_address=self.peer_address)
			]
		else:
			parts = [
				'message_type={message_type}'.format(
					message_type=self.message_type),
				'transaction_id={transaction_id}'.format(
					transaction_id=self.transaction_id)
			]
		parts.append('options={options}'.format(options=self.options))
		return '{cls}({parts})'.format(
			cls=type(self).__name__,
			parts=','.join(parts)
		)

	def encode(self):
		return b''

	@classmethod
	def decode(cls, packet):
		packet = bytes(packet)
		message_type, = cls.MSG_TYPE_STRUCT.unpack_from(packet)
		try:
			message_type = MessageType(message_type)
		except ValueError:
			print('unknown value: %r')
			raise

		if message_type in (MessageType.RELAY_FORW, MessageType.RELAY_REPL):
			message_struct = cls.RELAY_AGENT_SERVER_STRUCT
			data = message_struct.unpack_from(packet)
			message_type, hop_count, link_address, peer_address = data
			kwargs = {
				'message_type': message_type,
				'hop_count': hop_count,
				'link_address': link_address,
				'peer_address': peer_address,
			}
		else:
			message_struct = cls.CLIENT_SERVER_STRUCT
			data = message_struct.unpack_from(packet)
			message_type, transaction_id = data
			kwargs = {
				'message_type': message_type,
				'transaction_id': transaction_id
			}
		kwargs['options'] = OptionMap.decode(packet[message_struct.size:])
		self = cls(**kwargs)
		return self

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
