"""dhcp.v6

Standards-compliant IPv6 DHCP implementation

"""

__author__ = 'Tori Wolf <wiredwolf@wiredwolf.gg>'
__date__ = '2023-09-15'
# SPDX-License-Identifier: MIT
__license__ = 'MIT'
__copyright__ = '2023 Tori Wolf'

try:
	from .message import *
	from .message import __all__ as message_all
	from .rfc8415 import *
	from .rfc8415 import __all__ as rfc8415_all
	from .optiontypes import (register as register_type,
		unregister as unregister_type, get as get_option)
	from .option_codecs import (register as register_codec,
		unregister as unregister_codec, get as get_codec,
		encode as encode_option, decode as decode_option)
except ImportError as e:
	print('Could not import DHCP')
	raise

option_codecs_all = ['register_codec', 'unregister_codec', 'get_codec',
	'encode_option', 'decode_option']

optiontypes_all = ['register_type', 'unregister_type', 'get_option']

__all__ = [
	*message_all,
	*rfc8415_all,
	*option_codecs_all,
	*optiontypes_all
]

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
