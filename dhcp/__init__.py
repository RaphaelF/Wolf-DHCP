"""DHCP

Standards-compliant DHCP implementation

"""

__author__ = 'Tori Wolf <wiredwolf@wiredwolf.gg>'
__version__ = '0.0.1'
__date__ = '2023-09-07'
# SPDX-License-Identifier: MIT
__license__ = 'MIT'
__copyright__ = '2023 Tori Wolf'

try:
	from . import v4 as ipv4
	from . import v6 as ipv6
except ImportError as e:
	print('Could not import DHCP: %r' % e)
	raise

__all__ = ['ipv4', 'ipv6']

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
