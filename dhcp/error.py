# SPDX-License-Identifier: MIT

__all__ = ['DHCPv4Error', 'DHCPv6Error']


class Error(Exception):
	"""Base class for DHCP errors"""
	pass


class DHCPv4Error(Error):
	"""Base class for DHCPv4 errors"""
	pass


class DHCPv6Error(Error):
	"""Base class for DHCPv6 errors"""
	pass

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
