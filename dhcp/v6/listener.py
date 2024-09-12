# SPDX-License-Identifier: MIT

import socket

from ..platform_specific import multicast_listen

DHCP_ADDRESS = 'ff02::1:2'
DHCP_TYPE = socket.SOCK_DGRAM

DHCP_CLIENT_PORT = 546
DHCP_SERVER_PORT = 547


def listen():
	return multicast_listen(DHCP_ADDRESS, DHCP_SERVER_PORT, DHCP_TYPE)

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
