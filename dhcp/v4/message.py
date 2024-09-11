# SPDX-License-Identifier: MIT

__all__ = ['Operation', 'HardwareType', 'Flags', 'MessageType', 'BOOTP',
	'DHCP']

import enum
import struct
from collections import namedtuple
from ipaddress import IPv4Address
from random import randrange
from warnings import warn

try:
	from ..hardwaretype import HardwareType
except ImportError:
	# NOTE(tori): pretty much every network has settled on ethernet
	# encapsulation if you're doing something esoteric, please let me know, and
	# I'll add support, but I don't think any other DHCP servers have put in
	# much effort to implement other hardware types
	@enum.unique
	class HardwareType(enum.IntEnum):
		ETH10MB = 1

# NOTE(tori): the rfc2132 import also registers the option type, so don't
# remove it
from .rfc2132 import RFC2132OptionType, rfc2132_option_codec
from .optiontypes import get as get_option
from .option_codecs import encode as encode_option, decode as decode_option
from ..error import DHCPv4Error


# NOTE(tori): this will actually protect earlier versions if we test using
# python3 versions with enums and don't generate enums dynamically
@enum.unique
class Operation(enum.IntEnum):
	REQUEST = 1
	REPLY = 2


@enum.unique
class Flags(enum.IntFlag):
	BROADCAST = 1 << 15


@enum.unique
class MessageType(enum.IntEnum):
	DISCOVER = 1
	OFFER = 2
	REQUEST = 3
	DECLINE = 4
	ACK = 5
	NAK = 6
	RELEASE = 7
	INFORM = 8


class OptionMap:
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
				if tag == RFC2132OptionType.PAD:
					continue
				if tag == RFC2132OptionType.END:
					break

				if tag not in options:
					options[tag] = value
				else:
					options[tag] += value
		else:
			raise TypeError('not supported: %r' % options)

		return options

	@staticmethod
	def encode_options(options):
		result = {}
		for key, value in options.items():
			try:
				result[get_option(key)] = encode_option(key, value)
			except Exception as e:
				print('Could not encode value %r for option %r' % (value, key))
				raise e
		return result

	def __init__(self, values=None):
		values = self.check_options(values)
		self._options = values

	def __getitem__(self, key):
		key = get_option(key, ignore_unknown=True)
		if key in (RFC2132OptionType.PAD, RFC2132OptionType.END):
			return
		return decode_option(key, self._options.__getitem__(key),
			ignore_unknown=True)

	def __setitem__(self, key, value):
		key = get_option(key, ignore_unknown=True)
		if key in (RFC2132OptionType.PAD, RFC2132OptionType.END):
			return
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

	def encode(self, pad_length=None):
		opts = b''
		for key, value in self._options.items():
			while len(value) > 255:
				opts += bytes([key, 255, *value[:255]])
				value = value[255:]
			opts += bytes([key, len(value), *value])
		opts += b'\xFF'
		if pad_length is not None:
			pad_needed = max(0, pad_length - len(opts))
			opts += b'\x00'*pad_needed
		return opts

	@staticmethod
	def decode_bytes(raw_data):
		options = []

		option_tag = 0x00
		option_data = b''
		skip = 0

		while option_tag != 0xFF:
			if not raw_data:
				print('no end tag')
				break
			raw_data = raw_data[skip:]

			option_tag = get_option(raw_data[0], ignore_unknown=True)
			if option_tag in (0x00, 0xFF):
				option_data = b''
				skip = 1
			else:
				option_length = raw_data[1]
				option_data = raw_data[2:2 + option_length]
				skip = 2 + option_length
			options.append((option_tag, option_data))

		return options

	@classmethod
	def decode_from_packet(cls, packet):
		if not packet.is_magic_cookie_ok():
			raise DHCPv4Error('malformed packet: %r' % packet)
		raw_data = packet.raw_data['vend'][len(DHCP_MAGIC_COOKIE):]

		options = cls.decode_bytes(raw_data)

		option_overload = None
		for option_tag, option_value in options:
			# NOTE(tori): we take the last instance rather than outright
			# rejecting the packet (in case of multiple occurrences), because
			# we're nice like that
			# NOTE(tori): option tag 52 is option overload tag, which can have
			# a single byte with the value of 1, 2, or 3, representing options
			# in 'file', 'sname', or 'file' and 'sname', respectively
			if option_tag == 52:
				option_overload, = struct.unpack('!B', option_value)
				if option_overload not in (1, 2, 3):
					print('invalid option overload: %r, ignoring'
						% option_overload)
					option_overload = None
		if option_overload is not None:
			if option_overload & 0x1:
				options = [
					*options,
					*cls.decode_bytes(packet.raw_data['file'])
				]
			if option_overload & 0x2:
				options = [
					*options,
					*cls.decode_bytes(packet.raw_data['sname'])
				]

		return cls(options)

	def asdict(self):
		return {**self._options}


class BOOTP:
	NAMES = namedtuple('Fields', 'op htype hlen hops xid secs ciaddr yiaddr'
		' siaddr giaddr chaddr sname file vend', defaults=(None,)*14)
	CODEC = struct.Struct(
		'!'			# network byte order (big)
		'BBBB'		# op, htype, hlen, hops
		'I'			# xid
		'H2x'		# secs, 2 unused bytes
		'4s'		# ciaddr (client ip)
		'4s'		# yiaddr (given ip by server)
		'4s'		# siaddr (server ip address)
		'4s'		# giaddr (gateway ip address)
		'16s'		# chaddr (client hardware address)
		'64s'		# server host name (null-terminated)
		'128s'		# boot file name (null-terminated)
		'64s'		# vendor-specific area
	)

	@property
	def operation(self):
		return Operation(self.raw_data['op'])

	@operation.setter
	def operation(self, value):
		self.raw_data['op'] = Operation(value).value

	@property
	def hardware_type(self):
		return HardwareType(self.raw_data['htype'])

	@hardware_type.setter
	def hardware_type(self, value):
		self.raw_data['htype'] = HardwareType(value).value

	@property
	def hardware_address(self):
		return self.raw_data['chaddr'][:self.raw_data['hlen']]

	@hardware_address.setter
	def hardware_address(self, value):
		if len(value) > 16:
			raise DHCPv4Error('hardware address too long: `%r`' % value)
		self.raw_data['chaddr'] = (
			bytes(value) + b'\0'*16
		)[:16]
		self.raw_data['hlen'] = len(value)

	@property
	def hops(self):
		return self.raw_data['hops']

	@hops.setter
	def hops(self, value):
		if value not in range(0x100):
			raise DHCPv4Error('`%r` not in range(0x100)' % value)
		self.raw_data['hops'] = value

	@property
	def transaction_id(self):
		return self.raw_data['xid']

	@transaction_id.setter
	def transaction_id(self, value):
		if value not in range(0x100000000):
			raise DHCPv4Error('`%r` not in range(0x100000000)' % value)
		self.raw_data['xid'] = value

	@property
	def seconds(self):
		return self.raw_data['secs']

	@seconds.setter
	def seconds(self, value):
		if value not in range(0x10000):
			raise DHCPv4Error('`%r` not in range(0x10000)' % value)
		self.raw_data['secs'] = value

	@property
	def client_ip(self):
		return IPv4Address(self.raw_data['ciaddr'])

	@client_ip.setter
	def client_ip(self, value):
		ip = IPv4Address(value)
		self.raw_data['ciaddr'] = ip.packed

	@property
	def your_ip(self):
		return IPv4Address(self.raw_data['yiaddr'])

	@your_ip.setter
	def your_ip(self, value):
		ip = IPv4Address(value)
		self.raw_data['yiaddr'] = ip.packed

	@property
	def server_ip(self):
		return IPv4Address(self.raw_data['siaddr'])

	@server_ip.setter
	def server_ip(self, value):
		ip = IPv4Address(value)
		self.raw_data['siaddr'] = ip.packed

	@property
	def gateway_ip(self):
		return IPv4Address(self.raw_data['giaddr'])

	@gateway_ip.setter
	def gateway_ip(self, value):
		ip = IPv4Address(value)
		self.raw_data['giaddr'] = ip.packed

	@property
	def server_name(self):
		return self.raw_data['sname'].rstrip(b'\0')

	@server_name.setter
	def server_name(self, value):
		data = value
		if len(data) > 64:
			raise DHCPv4Error('encoded server name too long: `%r`' % value)
		self.raw_data['sname'] = (
			data + b'\0'*64
		)[:64]

	@property
	def boot_file_name(self):
		return self.raw_data['file'].rstrip(b'\0')

	@boot_file_name.setter
	def boot_file_name(self, value):
		data = value
		if len(data) > 128:
			raise DHCPv4Error('encoded boot file name too long: `%r`' % value)
		self.raw_data['file'] = (
			data + b'\0'*128
		)[:128]

	@property
	def vendor(self):
		return self.raw_data['vend']

	@vendor.setter
	def vendor(self, value):
		data = bytes(value)
		if len(data) > 64:
			raise DHCPv4Error('vendor data too long: `%r`' % value)
		self.raw_data['vend'] = (
			data + b'\0'*64
		)

	def __init__(self, *, op, htype=HardwareType.ETH10MB, hops=0, xid=None,
		secs=0, ciaddr=0, yiaddr=0, siaddr=0, giaddr=0,
		hwaddr=b'\x00\x00\x00\x00\x00\x00', sname=b'', file=b'', vend=b''):
		self.raw_data = self.NAMES()._asdict()
		self.operation = op
		self.hardware_type = htype
		self.hops = hops
		if xid is None:
			xid = randrange(0x100000000)
		self.transaction_id = xid
		self.seconds = secs
		self.client_ip = ciaddr
		self.your_ip = yiaddr
		self.server_ip = siaddr
		self.gateway_ip = giaddr
		self.hardware_address = hwaddr
		self.server_name = sname
		self.boot_file_name = file
		self.vendor = vend

	def _repr_parts(self):
		return (
			'operation={op}'.format(op=self.operation),
			'hardware_type={htype}'.format(htype=self.hardware_type),
			'hardware_address={hwaddr}'.format(hwaddr=self.hardware_address),
			'hops={hops}'.format(hops=hex(self.hops)),
			'transaction_id={xid}'.format(xid=hex(self.transaction_id)),
			'seconds={secs}'.format(secs=self.seconds),
			'client_ip={ciaddr}'.format(ciaddr=self.client_ip),
			'your_ip={yiaddr}'.format(yiaddr=self.your_ip),
			'server_ip={siaddr}'.format(siaddr=self.server_ip),
			'gateway_ip={giaddr}'.format(giaddr=self.gateway_ip),
			'server_name={sname!r}'.format(sname=self.server_name),
			'boot_file_name={file!r}'.format(file=self.boot_file_name),
			'vendor={vend!r}'.format(vend=self.vendor)
		)

	def __repr__(self):
		return '{cls}({parts})'.format(
			cls=type(self).__name__,
			parts=','.join(self._repr_parts())
		)

	def encode(self):
		ordered_data = [self.raw_data[field] for field in self.NAMES._fields]
		return self.CODEC.pack(*ordered_data)

	@classmethod
	def decode(cls, packet):
		packet = bytes(packet)
		self = cls(op=Operation.REQUEST)
		data = cls.CODEC.unpack(packet[:cls.CODEC.size])
		structured_data = cls.NAMES._make(data)
		self.raw_data = structured_data._asdict()
		return self


DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'


class DHCP(BOOTP):
	NAMES = namedtuple('Fields', 'op htype hlen hops xid secs flags ciaddr'
		' yiaddr siaddr giaddr chaddr sname file', defaults=(None,)*14)
	CODEC = struct.Struct(
		'!'			# network byte order (big)
		'BBBB'		# op, htype, hlen, hops
		'I'			# xid
		'HH'		# secs, flags
		'4s'		# ciaddr (client ip)
		'4s'		# yiaddr (given ip by server)
		'4s'		# siaddr (server ip address)
		'4s'		# giaddr (gateway ip address)
		'16s'		# chaddr (client hardware address)
		'64s'		# server host name (null-terminated)
		'128s'		# boot file name (null-terminated)
		# '312s'	# dhcp options (parsing in `decode()`)
	)

	@property
	def flags(self):
		return Flags(self.raw_data['flags'])

	@flags.setter
	def flags(self, value):
		if value not in range(0x10000):
			raise DHCPv4Error('`%r` not in range(0x10000)' % value)
		self.raw_data['flags'] = Flags(value)

	@property
	def vendor(self):
		warn('use .options instead of .vendor for DHCP', DeprecationWarning)
		return super().vendor

	@vendor.setter
	def vendor(self, value):
		warn('use .options instead of .vendor for DHCP', DeprecationWarning)
		super().vendor = value

	@property
	def options(self):
		if not hasattr(self, '_opts'):
			self._opts = OptionMap.decode_from_packet(self)
		return self._opts

	@property
	def magic_cookie(self):
		return self.raw_data['vend'][:len(DHCP_MAGIC_COOKIE)]

	def __init__(self, *, op, htype=HardwareType.ETH10MB, hops=0, xid=None,
		secs=0, flags=0, ciaddr=0, yiaddr=0, siaddr=0, giaddr=0,
		hwaddr=b'\x00\x00\x00\x00\x00\x00', sname=b'', file=b''):
		self.raw_data = self.NAMES()._asdict()
		self.operation = op
		self.hardware_type = htype
		self.hops = hops
		if xid is None:
			xid = randrange(0x100000000)
		self.transaction_id = xid
		self.seconds = secs
		self.flags = flags
		self.client_ip = ciaddr
		self.your_ip = yiaddr
		self.server_ip = siaddr
		self.gateway_ip = giaddr
		self.hardware_address = hwaddr
		self.server_name = sname
		self.boot_file_name = file
		self.raw_data['vend'] = DHCP_MAGIC_COOKIE

	def is_magic_cookie_ok(self):
		return self.magic_cookie == DHCP_MAGIC_COOKIE

	def _repr_parts(self):
		return (
			'operation={op}'.format(op=self.operation),
			'hardware_type={htype}'.format(htype=self.hardware_type),
			'hardware_address={hwaddr}'.format(hwaddr=self.hardware_address),
			'hops={hops}'.format(hops=hex(self.hops)),
			'transaction_id={xid}'.format(xid=hex(self.transaction_id)),
			'seconds={secs}'.format(secs=self.seconds),
			'client_ip={ciaddr}'.format(ciaddr=self.client_ip),
			'your_ip={yiaddr}'.format(yiaddr=self.your_ip),
			'server_ip={siaddr}'.format(siaddr=self.server_ip),
			'gateway_ip={giaddr}'.format(giaddr=self.gateway_ip),
			'server_name={sname!r}'.format(sname=self.server_name),
			'boot_file_name={file!r}'.format(file=self.boot_file_name),
			'options={options!r}'.format(options=self.options)
		)

	# TODO(tori): add support for option overload in encode() function
	def encode(self):
		base_encoded = super().encode()
		return base_encoded + DHCP_MAGIC_COOKIE + self.options.encode()

	@classmethod
	def decode(cls, packet):
		packet = bytes(packet)
		self = super(cls, cls).decode(packet)
		self.raw_data['vend'] = packet[cls.CODEC.size:]
		if not self.is_magic_cookie_ok():
			warn('bad magic cookie: {cookie}'.format(cookie=self.magic_cookie))
		return self

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
