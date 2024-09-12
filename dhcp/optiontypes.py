# SPDX-License-Identifier: MIT

__all__ = ['TypeRegistry', 'TypeList']


class TypeRegistry:
	def __init__(self):
		self.OptionTypes = []

	def register(self, OptionType, priority=None):
		if priority is None:
			priority = len(self.OptionTypes)
		self.OptionTypes.insert(priority, OptionType)

	def unregister(self, OptionType):
		try:
			self.OptionTypes.remove(OptionType)
		except ValueError:
			pass

	def get(self, value, ignore_unknown=False):
		for OptionType in self.OptionTypes:
			try:
				return OptionType(value)
			except ValueError:
				continue
		else:
			if ignore_unknown:
				return value
			else:
				raise ValueError(
					'%r is not a valid option for all registered option types'
					% value
				)


class TypeList:
	def __init__(self, registry, ntypes=256):
		self.ntypes = ntypes
		self.registry = registry

	def __getitem__(self, index):
		if index not in range(self.ntypes):
			raise IndexError('%r is not an option type' % index)
		return self.registry.get(index, ignore_unknown=True)

	def __iter__(self):
		return (self.registry.get(n, ignore_unknown=True)
			for n in range(self.ntypes))

# NOTE(tori): option type enumerations SHOULD be of the format
# <name>OptionType and be a subclass of enum.IntEnum

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
