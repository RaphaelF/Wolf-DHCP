# SPDX-License-Identifier: MIT

def write_hexdump(data, filename="wireshark-hexdump.txt"):
	data = bytes(data)
	with open(filename, 'w') as hexdump:
		for i in range(0, len(data), 0x10):
			offset = '%08X' % i
			row = ' '.join('%02X' % byte for byte in data[i:i + 0x10])
			hexdump.write('%s:\t%s\n' % (offset, row))

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
