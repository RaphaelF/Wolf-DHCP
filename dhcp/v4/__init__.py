"""dhcp.v4

Standards-compliant IPv4 DHCP implementation

"""

__author__ = 'Tori Wolf <wiredwolf@wiredwolf.gg>'
__date__ = '2022-06-27'
# SPDX-License-Identifier: MIT
__license__ = 'MIT'
__copyright__ = '2022 Tori Wolf'

try:
	from .message import *
	from .message import __all__ as message_all
	from .rfc2132 import *
	from .rfc2132 import __all__ as rfc2132_all
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
	*rfc2132_all,
	*option_codecs_all,
	*optiontypes_all
]

# NOTE(tori): rfc2131 - done
# NOTE(tori): rfc2132 - done
# NOTE(tori): rfc3396 - done
# XXX(tori): rfc4361 - what we're doing seems to be according to spec; it seems to be mostly client-specific, so long as we don't try and parse client identifiers
# NOTE(tori): rfc6842 - done

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
