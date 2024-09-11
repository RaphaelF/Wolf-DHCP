# SPDX-License-Identifier: MIT

__all__ = ['CodecError', 'Codec', 'CodecRegistry']


class CodecError(Exception):
	pass


class Codec:
	def __init__(self, *, name=None, codecs=None):
		if name is None:
			name = 'codec_%s' % id(self)
		self.name = name
		if codecs is None:
			codecs = {}
		self.codecs = codecs

	def get_codec(self, option):
		try:
			return self.codecs[option]
		except KeyError:
			raise CodecError('option %r cannot be encoded by this codec (%s)'
				% (option, self.name)
			) from None
	# def get_encoder(self, option):
	# 	encoder, decoder = self.get_codec(option)
	# 	return encoder
	# def get_decoder(self, option):
	# 	encoder, decoder = self.get_codec(option)
	# 	return decoder


class CodecRegistry:
	def __init__(self):
		self.option_codecs = []

	def register(self, option_codec, priority=None):
		if not isinstance(option_codec, Codec):
			raise CodecError('%r is not an instance of Codec' % option_codec)
		if priority is None:
			priority = len(self.option_codecs)
		self.option_codecs.insert(priority, option_codec)

	def unregister(self, option_codec):
		try:
			self.option_codecs.remove(option_codec)
		except ValueError:
			pass

	def get(self, value, ignore_unknown=True):
		for option_codec in self.option_codecs:
			try:
				return option_codec.get_codec(value)
			except CodecError:
				continue
		else:
			if ignore_unknown:
				def encoder(value):
					return value

				def decoder(value):
					return value
				return encoder, decoder
			else:
				raise ValueError(
					'%r is not a valid option for for all registered option codecs'
					% value
				)

	def encode(self, option, value, ignore_unknown=True):
		encoder, decoder = self.get(option, ignore_unknown)
		return encoder(value)

	def decode(self, option, value, ignore_unknown=True):
		encoder, decoder = self.get(option, ignore_unknown)
		return decoder(value)

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
