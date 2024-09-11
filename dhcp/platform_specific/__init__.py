# SPDX-License-Identifier: CC0-1.0

__all__ = ['get_mask_from_iface', 'get_ip_from_iface', 'get_mac_from_iface',
	'list_ifaces', 'broadcast_listen', 'multicast_listen']

from importlib import import_module
from platform import system

platform = {
	'Linux': 'linux',
	'Windows': None,
	'Darwin': None
}.get(system(), None)

if platform is None:
	raise Exception('unsupported platform: %s' % platform)

platform_lib = import_module('.%s' % platform, package=__name__)

for name in __all__:
	globals()[name] = getattr(platform_lib, name)

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
