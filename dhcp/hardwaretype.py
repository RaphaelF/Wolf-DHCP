# SPDX-License-Identifier: MIT

import enum

# NOTE(tori): hardware types come from the following:
# https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml

@enum.unique
class HardwareType(enum.IntEnum):
	RESERVED = 0
	ETH10MB = 1
	EXPERIMENTAL_ETHERNET = 2
	AX25 = 3
	LOCALTALK = 11
	FIBRE_CHANNEL = 18
	IEEE_1394 = 24
	IPSEC_TUNNEL = 31
	INFINIBAND = 32

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
