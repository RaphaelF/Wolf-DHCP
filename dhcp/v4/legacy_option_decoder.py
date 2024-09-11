# SPDX-License-Identifier: MIT

def decode_options_from_bytes(raw_data):
	options = []

	option_tag = 0x00
	option_data = b''
	skip = 0

	while option_tag != 0xFF:
		if not raw_data:
			#print('no end tag')
			break
		raw_data = raw_data[skip:]

		option_tag = get_option(raw_data[0], ignore_unknown=True)
		if option_tag in (0x00, 0xFF):
			option_data = b''
			skip = 1
		else:
			option_length = raw_data[1]
			option_data = raw_data[2:2 + option_length]
			skip = 2 + option_length
		options.append((option_tag, option_data))
	return options

def decode_options_from_packet(packet):
	if not packet.is_magic_cookie_ok():
		raise Error('malformed packet: %r' % packet)
	raw_data = packet.raw_data['vend'][len(DHCP_MAGIC_COOKIE):]

	options = decode_options_from_bytes(raw_data)

	option_overload = None
	for option_tag, option_value in options:
		# NOTE(tori): we take the last instance rather than outright
		# rejecting the packet (in case of multiple occurrences), because we're
		# nice like that
		# NOTE(tori): option tag 52 is option overload tag, which can have a
		# single byte with the value of 1, 2, or 3, representing options in
		# 'file', 'sname', or 'file' and 'sname', respectively
		if option_tag == 52:
			option_overload, = struct.unpack('!B', option_value)
			if option_overload not in (1, 2, 3):
				print('invalid option overload: %r, ignoring'
					% option_overload)
				option_overload = None
	if option_overload is not None:
		if option_overload & 0x1:
			options = [
				*options,
				*decode_options_from_bytes(packet.raw_data['file'])
			]
		if option_overload & 0x2:
			options = [
				*options,
				*decode_options_from_bytes(packet.raw_data['sname'])
			]

	return options

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
