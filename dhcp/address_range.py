# SPDX-License-Identifier: MIT

__all__ = ['address_range']

from ipaddress import ip_address, AddressValueError

class address_range_iterator:
	def __init__(self, address_range_instance):
		self.address_range = address_range_instance
		self.offset = -self.address_range.step
	def __iter__(self):
		return self
	def __next__(self):
		try:
			current_offset = self.offset
			self.offset += self.address_range.step
			# NOTE(tori): AddressValueError MAY occur here
			result = self.address_range.start + self.offset
			if result > self.address_range.stop:
				# NOTE(tori): reset the offset so it doesn't grow infinitely
				self.offset = current_offset
				raise StopIteration
			return result
		except AddressValueError:
			raise StopIteration

class address_range:
	def __init__(self, start, stop, step=1):
		self.start = ip_address(start)
		self.stop = ip_address(stop)
		if step == 0:
			raise ValueError('%s() arg 3 must not be zero'
				% type(self).__name__)
		self.step = step
	def __contains__(self, address):
		# NOTE(tori): we could shorten this whole function to the following:
		# int(address) in range(int(start), int(stop), step)
		# but that depends on the range builtin, and I want to implement myself
		address = ip_address(address)

		address_relative = int(address) - int(self.start)
		in_range = self.start <= address <= self.stop
		in_step = address_relative%self.step == 0

		return in_range and in_step
	def __getitem__(self, index):
		negative_index_offset = int(self.stop) - int(self.start) + 1

		if isinstance(index, tuple):
			indices = index
			result = []
			for index in indices:
				if isinstance(index, int):
					result.append(self[index])
				elif isinstance(index, slice):
					result.extend(self[index])
				else:
					raise TypeError(
						'%s indices must be integers or slices, not %s'
						% (type(self).__name__, type(index).__name__))
			return result
		elif isinstance(index, slice):
#			return index

			start = 0 if index.start is None else index.start
			if start < 0:
				start += negative_index_offset
			stop = len(self) - 1 if index.stop is None else index.stop
			if stop < 0:
				stop += negative_index_offset
			step = 1 if index.step is None else index.step

			if stop < start:
				return type(self)(0, 0)

			return type(self)(self[start], self[stop], step)
		elif isinstance(index, int):
			if index < 0:
				index += negative_index_offset
			if index not in range(0, len(self)):
				raise IndexError('%s index out of range' % type(self).__name__)
			return self.start + index
		else:
			raise TypeError('%s indices must be integers or slices, not %s'
				% (type(self).__name__, type(index).__name__))
	def __len__(self):
		if self.stop < self.start:
			return 0
		distance = int(self.stop) - int(self.start)
		return int(distance/self.step) + 1
	def __iter__(self):
		return address_range_iterator(self)
	def __repr__(self):
		if self.step != 1:
			return '%s(%r, %r, %r)' % (
				type(self).__name__,
				self.start,
				self.stop,
				self.step
			)
		return '%s(%r, %r)' % (
			type(self).__name__,
			self.start,
			self.stop
		)

#def xaddress_range(start, stop, step=1):
#	"""Generate an address range from `start` to `stop` inclusive.
#
#	N.B. The address range is right-inclusive because IPv4Address does not
#	support addresses with octets greater than 256, as it shouldn't.
#	"""
#
#	start = IPv4Address(start)
#	stop = IPv4Address(stop)
#
#	current = start
#	while current <= stop:
#		yield current
#		try:
#			current += step
#		except AddressValueError:
#			# NOTE(tori): accounts for edge case when range goes to
#			# 255.255.255.255
#			break

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
