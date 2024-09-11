# SPDX-License-Identifier: MIT

from ..option_codecs import CodecError, Codec, CodecRegistry

registry = CodecRegistry()

register = registry.register
unregister = registry.unregister
get = registry.get
encode = registry.encode
decode = registry.decode

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
