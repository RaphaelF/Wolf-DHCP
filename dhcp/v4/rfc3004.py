# SPDX-License-Identifier: MIT

__all__ = ['RFC3004OptionType', 'rfc3004_option_codec']

import enum

from .optiontypes import register as register_optiontype
from .option_codecs import register as register_optioncodec, Codec

class RFC3004OptionType(enum.IntEnum):
	USER_CLASS_IDENTIFIER = 77

# NOTE(tori): these are identity functions because iPXE is weird

def encode_user_class_identifier(decoded):
	return decoded

def decode_user_class_identifier(encoded):
	return encoded

rfc3004_option_codec = Codec(
	name='rfc3004',
	codecs={
		RFC3004OptionType.USER_CLASS_IDENTIFIER: (
			encode_user_class_identifier,
			decode_user_class_identifier
		),
	}
)

register_optiontype(RFC3004OptionType)
register_optioncodec(rfc3004_option_codec)

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
