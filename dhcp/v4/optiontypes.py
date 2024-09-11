# SPDX-License-Identifier: MIT

from ..optiontypes import TypeRegistry, TypeList

registry = TypeRegistry()

register = registry.register
unregister = registry.unregister
get = registry.get

typelist = TypeList(registry, 256)

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
