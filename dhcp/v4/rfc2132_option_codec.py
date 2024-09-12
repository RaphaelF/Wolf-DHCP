# SPDX-License-Identifier: MIT

from functools import wraps
from ipaddress import IPv4Address
from struct import Struct
from .option_codecs import register as register_optioncodec, Codec
from .rfc2132optiontype import RFC2132OptionType

# NOTE(tori): the way this modules is implemented is ugly, but the
# optioncodec API is beautiful
# TODO(tori): rewrite in a less disgusting way

# XXX(tori): here be dragons

boolean = Struct('!?')
int8 = Struct('!b')
uint8 = Struct('!B')
int16 = Struct('!h')
uint16 = Struct('!H')
int32 = Struct('!i')
uint32 = Struct('!I')


def make_unpacker(struct):
	def unpacker(b):
		result, = struct.unpack(b)
		return result
	return unpacker


def make_guarded(fn, check=lambda _: True, exc=None):
	@wraps(fn)
	def wrapper(*args, **kwargs):
		if not check(*args, **kwargs):
			nonlocal exc
			print(exc)
			if exc is None:
				exc = Exception('invalid function call: %s(*%r, **%r)' % (
					fn.__name__, args, kwargs))
			elif isinstance(exc, type) and issubclass(exc, BaseException):
				# NOTE(tori): just raise the bare error
				pass
			elif isinstance(exc, str):
				exc = ValueError(exc)
			elif callable(exc):
				exc = exc(args, kwargs)
			raise exc
		return fn(*args, **kwargs)
	return wrapper


def encode_netbios_node_type(decoded):
	if decoded not in (0x1, 0x2, 0x4, 0x8):
		raise ValueError('invalid NetBIOS over TCP/IP Node Type value')
	return uint8.pack(decoded)


def decode_netbios_node_type(encoded):
	return uint8.unpack(encoded)


def encode_empty(decoded):
	return b''


def decode_empty(encoded):
	return None


def encode_ip(decoded):
	try:
		return IPv4Address(decoded).packed
	except Exception:
		raise ValueError('invalid decoded IP: %r' % decoded)


def decode_ip(encoded):
	try:
		return IPv4Address(encoded)
	except Exception:
		raise ValueError('invalid encoded IP: %r' % encoded)


def encode_ips(decoded):
	try:
		return b''.join(IPv4Address(value).packed for value in decoded)
	except Exception:
		raise ValueError('invalid encoded IP list: %r' % decoded)


def decode_ips(encoded):
	if len(encoded)%4 != 0:
		raise ValueError('invalid decoded IP list: %r' % encoded)
	return [decode_ip(bytes(value)) for value in zip(*[iter(encoded)]*4)]


def encode_ip_pairs(decoded):
	try:
		return b''.join(
			IPv4Address(pair[0]).packed + IPv4Address(pair[1]).packed
			for pair
			in decoded
		)
	except Exception:
		raise ValueError('invalid decoded IP pair list: %r' % decoded)


def decode_ip_pairs(encoded):
	if len(encoded)%8 != 0:
		raise ValueError('invalid encoded IP pair list: %r' % encoded)
	result = []
	for i in range(0, len(encoded), 8):
		first = IPv4Address(encoded[i + 0:i + 4])
		second = IPv4Address(encoded[i + 4:i + 8])
		result.append((first, second))
	return result


def encode_string(decoded):
	return decoded.encode('ascii')


def decode_string(encoded):
	return encoded.decode('ascii')


# NOTE(tori): guard only the encodes, per Postel's Law
bool_codec = (boolean.pack, make_unpacker(boolean))
empty_codec = (encode_empty, decode_empty)
ip_codec = (encode_ip, decode_ip)
ip_list_codec = (
	make_guarded(encode_ips, lambda lst: iter(lst) and len(lst) > 0),
	decode_ips
)
ip_pair_codec = (
	make_guarded(encode_ip_pairs, lambda lst: iter(lst) and len(lst) > 0),
	decode_ip_pairs
)
string_codec = (
	make_guarded(encode_string, lambda s: len(s) > 0), decode_string
)
uint32_codec = (uint32.pack, make_unpacker(uint32))

rfc2132_option_codec = Codec(
	name='rfc2132',
	codecs={
		RFC2132OptionType.PAD: empty_codec,
		RFC2132OptionType.END: empty_codec,
		# XXX(tori): is there a better way? this feels weird calling an IP a
		# mask
		RFC2132OptionType.SUBNET_MASK: ip_codec,
		RFC2132OptionType.TIME_OFFSET: (int32.pack, make_unpacker(int32)),
		RFC2132OptionType.ROUTER: ip_list_codec,
		RFC2132OptionType.TIME_SERVER: ip_list_codec,
		RFC2132OptionType.NAME_SERVER: ip_list_codec,
		RFC2132OptionType.DOMAIN_NAME_SERVER: ip_list_codec,
		RFC2132OptionType.LOG_SERVER: ip_list_codec,
		RFC2132OptionType.COOKIE_SERVER: ip_list_codec,
		RFC2132OptionType.LPR_SERVER: ip_list_codec,
		RFC2132OptionType.IMPRESS_SERVER: ip_list_codec,
		RFC2132OptionType.RESOURCE_LOCATION_SERVER: ip_list_codec,
		RFC2132OptionType.HOST_NAME: string_codec,
		RFC2132OptionType.BOOT_FILE_SIZE: (
			uint16.pack, make_unpacker(uint16)
		),
		RFC2132OptionType.MERIT_DUMP_FILE: string_codec,
		RFC2132OptionType.DOMAIN_NAME: string_codec,
		RFC2132OptionType.SWAP_SERVER: ip_codec,
		RFC2132OptionType.ROOT_PATH: string_codec,
		RFC2132OptionType.EXTENSIONS_PATH: string_codec,
		RFC2132OptionType.IP_FORWARDING_ENABLE: bool_codec,
		RFC2132OptionType.NONLOCAL_SOURCE_ROUTING_ENABLE: bool_codec,
		RFC2132OptionType.POLICY_FILTER: ip_pair_codec,
		RFC2132OptionType.MAXIMUM_DATAGRAM_REASSEMBLY_SIZE: (
			make_guarded(uint16.pack, lambda n: n >= 576,
				'maximum datagram reassembly size must be at least 576'),
			make_unpacker(uint16)
		),
		RFC2132OptionType.DEFAULT_IP_TTL: (
			make_guarded(uint8.pack, lambda n: n > 0,
				'value must be greater than 0'),
			make_unpacker(uint8)
		),
		RFC2132OptionType.PATH_MTU_AGING_TIMEOUT: uint32_codec,
		RFC2132OptionType.PATH_MTU_PLATEAU_TABLE: (
			make_guarded(
				lambda lst: b''.join(uint16.pack(elt) for elt in lst),
				lambda lst: all(elt >= 68 for elt in lst),
				'MTU must be at least 68'
			),
			lambda b: [uint16.unpack(bytes(v))[0] for v in zip(*[iter(b)]*2)]
		),
		RFC2132OptionType.INTERFACE_MTU: (uint16.pack, make_unpacker(uint16)),
		RFC2132OptionType.ALL_SUBNETS_ARE_LOCAL: bool_codec,
		RFC2132OptionType.BROADCAST_ADDRESS: ip_codec,
		RFC2132OptionType.PERFORM_MASK_DISCOVERY: bool_codec,
		RFC2132OptionType.MASK_SUPPLIER: bool_codec,
		RFC2132OptionType.PERFORM_ROUTER_DISCOVERY: bool_codec,
		RFC2132OptionType.ROUTER_SOLICITATION_ADDRESS: ip_codec,
		RFC2132OptionType.STATIC_ROUTE: ip_pair_codec,
		RFC2132OptionType.TRAILER_ENCAPSULATION: bool_codec,
		RFC2132OptionType.ARP_CACHE_TIMEOUT: uint32_codec,
		RFC2132OptionType.ETHERNET_ENCAPSULATION: bool_codec,
		RFC2132OptionType.TCP_DEFAULT_TTL: (
			make_guarded(uint8.pack, lambda v: v > 0,
				'TCP default TTL must be at least 1'),
			make_unpacker(uint8)
		),
		RFC2132OptionType.TCP_KEEPALIVE_INTERVAL: uint32_codec,
		RFC2132OptionType.TCP_KEEPALIVE_GARBAGE: bool_codec,
		RFC2132OptionType.NETWORK_INFORMATION_SERVICE_DOMAIN: string_codec,
		RFC2132OptionType.NETWORK_INFORMATION_SERVERS: ip_list_codec,
		RFC2132OptionType.NETWORK_TIME_PROTOCOL_SERVERS: ip_list_codec,
		RFC2132OptionType.VENDOR_SPECIFIC_INFORMATION: (
			make_guarded(lambda v: v, lambda v: b'\x63\x82\x53\x63' not in v,
				'dhcp magic cookie must not exist in vendor specific data'),
			lambda b: b
		),
		RFC2132OptionType.NETBIOS_OVER_TCPIP_NAME_SERVER: ip_list_codec,
		RFC2132OptionType.NETBIOS_OVER_TCPIP_DATAGRAM_DISTRIBUTION_SERVER: (
			ip_list_codec
		),
		RFC2132OptionType.NETBIOS_OVER_TCPIP_NODE_TYPE: (
			make_guarded(uint8.pack, lambda v: v in (0x1, 0x2, 0x4, 0x8),
				'invalid NetBIOS over TCP/IP Node Type'),
			make_unpacker(uint8)
		),
		RFC2132OptionType.NETBIOS_OVER_TCPIP_SCOPE: string_codec,
		RFC2132OptionType.X_WINDOW_SYSTEM_FONT_SERVER: ip_list_codec,
		RFC2132OptionType.X_WINDOW_SYSTEM_DISPLAY_MANAGER: ip_list_codec,
		RFC2132OptionType.NETWORK_INFORMATION_SERVICE_PLUS_DOMAIN: (
			ip_list_codec
		),
		RFC2132OptionType.NETWORK_INFORMATION_SERVICE_PLUS_SERVERS: (
			ip_list_codec
		),
		RFC2132OptionType.MOBILE_IP_HOME_AGENT: (
			encode_ips,
			decode_ips
		),
		RFC2132OptionType.SIMPLE_MAIL_TRANSPORT_PROTOCOL_SERVER: (
			ip_list_codec
		),
		RFC2132OptionType.POST_OFFICE_PROTOCOL_SERVER: ip_list_codec,
		RFC2132OptionType.NETWORK_NEWS_TRANSPORT_PROTOCOL: ip_list_codec,
		RFC2132OptionType.DEFAULT_WORLD_WIDE_WEB_SERVER: ip_list_codec,
		RFC2132OptionType.DEFAULT_FINGER_SERVER: ip_list_codec,
		RFC2132OptionType.DEFAULT_INTERNET_RELAY_CHAT_SERVER: ip_list_codec,
		RFC2132OptionType.STREETTALK_SERVER: ip_list_codec,
		RFC2132OptionType.STREETTALK_DIRECTORY_ASSISTANCE_SERVER: (
			ip_list_codec
		),
		RFC2132OptionType.REQUESTED_IP_ADDRESS: ip_codec,
		RFC2132OptionType.IP_ADDRESS_LEASE_TIME: uint32_codec,
		RFC2132OptionType.OPTION_OVERLOAD: (
			make_guarded(uint8.pack, lambda v: v in (1, 2, 3),
				'invalid option overload value'),
			make_unpacker(uint8)
		),
		RFC2132OptionType.TFTP_SERVER_NAME: string_codec,
		RFC2132OptionType.BOOTFILE_NAME: string_codec,
		RFC2132OptionType.MESSAGE_TYPE: (
			make_guarded(uint8.pack, lambda v: v in range(1, 9),
				'invalid message type value'),
			make_unpacker(uint8)
		),
		RFC2132OptionType.SERVER_IDENTIFIER: ip_codec,
		RFC2132OptionType.PARAMETER_REQUEST_LIST: (
			lambda v: bytes(v),
			lambda b: bytes(b)
		),
		RFC2132OptionType.MESSAGE: string_codec,
		RFC2132OptionType.MAXIMUM_DHCP_MESSAGE_SIZE: (
			make_guarded(uint16.pack, lambda n: n >= 576,
				'maximum DHCP reassembly size must be at least 576'),
			make_unpacker(uint16)
		),
		RFC2132OptionType.RENEWAL_TIME_VALUE: uint32_codec,
		RFC2132OptionType.REBINDING_TIME_VALUE: uint32_codec,
		RFC2132OptionType.VENDOR_CLASS_IDENTIFIER: (
			make_guarded(lambda v: bytes(v), lambda v: len(v) > 0),
			lambda b: bytes(b)
		),
		RFC2132OptionType.CLIENT_IDENTIFIER: (
			make_guarded(lambda v: bytes(v), lambda v: len(v) > 1),
			lambda b: bytes(b)
		)
	}
)

register_optioncodec(rfc2132_option_codec)

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
