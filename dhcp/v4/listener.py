# SPDX-License-Identifier: MIT

import socket

from ..platform_specific import broadcast_listen

DHCP_ADDRESS = '0.0.0.0'
DHCP_TYPE = socket.SOCK_DGRAM

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68


def listen(iface):
	return broadcast_listen(DHCP_ADDRESS, DHCP_SERVER_PORT, DHCP_TYPE,
		interface=iface)

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
