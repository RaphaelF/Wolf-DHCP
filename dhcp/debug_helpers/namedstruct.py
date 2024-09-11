# SPDX-License-Identifier: MIT

from re import compile as Regex
from struct import Struct
from collections import namedtuple as NamedTuple

INTEGER = r'[0-9]+'
FORMAT_NAME = r'[a-zA-Z_][a-zA-Z0-9_]*'
PAD_FORMAT_CHAR = r'x'
NONPAD_FORMAT_CHAR = r'[cbB\?hHiIlLqQnNefdspP]'
ENDIAN_FORMAT = r'[@<>!]?'
NAMED_FORMAT = r'{%s!(?:%s)?%s}' % (FORMAT_NAME, INTEGER, NONPAD_FORMAT_CHAR)
PAD_FORMAT = r'(?:%s)?%s' % (INTEGER, PAD_FORMAT_CHAR)
format_expression = Regex(r'^(%s)((?:%s|%s)*)$' % (ENDIAN_FORMAT, PAD_FORMAT,
	NAMED_FORMAT))
pad_expression = Regex('^(%s)' % PAD_FORMAT)
named_expression = Regex(r'{(%s)!((?:%s)?%s)}' % (FORMAT_NAME, INTEGER,
	NONPAD_FORMAT_CHAR))

# TODO(tori): a format like '!{value!4I}' is valid, but does not work, fixes:
# - remove ability to pass integer (would remove strings)
# - unpack in chunks (would be more complicated [multiple Structs required])

class error(Exception):
	pass

def parse_format(fmt):
	matches = format_expression.match(fmt)
	if matches is None:
		raise ValueError('improper format specification')
	endian, formats = matches.groups()

	result = [(endian,)]
	while formats:
		for expression in (pad_expression, named_expression):
			if (match := expression.match(formats)) is not None:
				result.append(match.groups()[::-1])
				formats = formats[match.end():]
				break
			else:
				continue
		else:
			raise Exception('this should never happen')

	return result

class NamedStruct:
	def __init__(self, fmt, name='StructValues', /):
		self.__name = name
		self.__raw_format = fmt
		self.__format = parse_format(self.format)
		self.recompute_format()
	def recompute_format(self):
		names = [fmt[1] for fmt in self.__format if len(fmt) == 2]
		formats = [fmt[0] for fmt in self.__format]
		self.__struct = Struct(''.join(formats))
		self.__namedtuple = NamedTuple(self.__name, ' '.join(names))
	def pack(self, **values):
		try:
			named_data = self.__namedtuple._make(
				values[field]
				for field
				in self.fields
			)
		except KeyError as e:
			raise error('missing value for packing: %s' % e.args) from None
		buffer = self.__struct.pack(*named_data)
		return buffer
	def pack_into(self, buffer, offset, **values):
		try:
			named_data = self.__namedtuple._make(
				values[field]
				for field
				in self.fields
			)
		except KeyError as e:
			raise error('missing value for packing: %s' % e.args) from None
		self.__struct.pack_into(buffer, offset, *named_data)
	def unpack(self, buffer):
		unpacked_data = self.__struct.unpack(buffer)
		named_data = self.__namedtuple._make(unpacked_data)
		return named_data
	def unpack_from(self, buffer, offset=0):
		unpacked_data = self.__struct.unpack_from(buffer, offset=offset)
		named_data = self.__namedtuple._make(unpacked_data)
		return named_data
	@property
	def format(self):
		return self.__raw_format
	@property
	def size(self):
		return self.__struct.size
	@property
	def struct_format(self):
		return self.__struct.format
	@property
	def fields(self):
		return self.__namedtuple._fields
	def __repr__(self):
		return '%s(%r)' % (type(self).__name__, self.format)

def pack(format, **values):
	_ = NamedStruct(format)
	return _.pack(**values)
def pack_into(format, buffer, offset, **values):
	_ = NamedStruct(format)
	return _.pack_into(buffer, offset, **values)
def unpack(format, buffer):
	_ = NamedStruct(format)
	return _.unpack(buffer)
def unpack_from(format, /, buffer, offset=0):
	_ = NamedStruct(format)
	return _.unpack_from(buffer, offset)

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
