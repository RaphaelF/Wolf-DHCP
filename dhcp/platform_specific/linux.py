# SPDX-License-Identifier: CC0-1.0

# XXX(tori): these methods are wonky, but save me from using `netifaces`;
# no problem with netifaces, but I would prefer to use only builtin modules

def get_mask_from_iface(ifname):
	# NOTE(tori): this method is portable, copy and paste it into any file

	# NOTE(tori): method adapted from https://stackoverflow.com/a/24196955
	# NOTE(tori): constant from net/if.h
	IF_NAMESIZE = 16
	# NOTE(tori): constant from sys/ioctl.h
	SIOCGIFNETMASK = 0x891B

	IPv4Address = __import__('ipaddress').IPv4Address
	socket = __import__('socket')
	ioctl = __import__('fcntl').ioctl
	pack = __import__('struct').pack

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	# NOTE(tori): fails on unassigned ip address with errno 99, which is
	# "Cannot assign requested address"
	# NOTE(tori): fails on invalid ip address with errno 19, which is "No
	# such device"
	ifreq = ioctl(
		sock.fileno(),
		SIOCGIFNETMASK,
		# NOTE(tori): the string size is arbitrarily chosen to be larger than
		# sizeof(struct ifreq) as far as the developer can tell; for more info,
		# see netdevice(7)
		pack('!256s', ifname[:IF_NAMESIZE - 1])
	)
	# NOTE(tori): find information in ip(7) as `struct sockaddr_in`
	packed = ifreq[20:24]

	return IPv4Address(packed)

def get_ip_from_iface(ifname):
	# NOTE(tori): this method is portable, copy and paste it into any file

	# NOTE(tori): method adapted from https://stackoverflow.com/a/24196955
	# NOTE(tori): constant from net/if.h
	IF_NAMESIZE = 16
	# NOTE(tori): constant from sys/ioctl.h
	SIOCGIFADDR = 0x8915

	IPv4Address = __import__('ipaddress').IPv4Address
	socket = __import__('socket')
	ioctl = __import__('fcntl').ioctl
	pack = __import__('struct').pack

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	# NOTE(tori): fails on unassigned ip address with errno 99, which is
	# "Cannot assign requested address"
	# NOTE(tori): fails on invalid ip address with errno 19, which is "No
	# such device"
	ifreq = ioctl(
		sock.fileno(),
		SIOCGIFADDR,
		# NOTE(tori): the string size is arbitrarily chosen to be larger than
		# sizeof(struct ifreq) as far as the developer can tell; for more info,
		# see netdevice(7)
		pack('!256s', ifname[:IF_NAMESIZE - 1])
	)
	# NOTE(tori): find information in ip(7) as `struct sockaddr_in`
	packed = ifreq[20:24]

	return IPv4Address(packed)

def get_mac_from_iface(ifname):
	# NOTE(tori): this method is portable, copy and paste it into any file

	# NOTE(tori): method adapted from https://stackoverflow.com/a/24196955
	# NOTE(tori): constant from net/if.h
	IF_NAMESIZE = 16
	# NOTE(tori): constant from sys/ioctl.h
	SIOCGIFHWADDR = 0x8927

	IPv4Address = __import__('ipaddress').IPv4Address
	socket = __import__('socket')
	ioctl = __import__('fcntl').ioctl
	pack = __import__('struct').pack

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	# NOTE(tori): fails on unassigned ip address with errno 99, which is
	# "Cannot assign requested address"
	# NOTE(tori): fails on invalid ip address with errno 19, which is "No
	# such device"
	ifreq = ioctl(
		sock.fileno(),
		SIOCGIFHWADDR,
		# NOTE(tori): the string size is arbitrarily chosen to be larger than
		# sizeof(struct ifreq) as far as the developer can tell; for more info,
		# see netdevice(7)
		pack('!256s', ifname[:IF_NAMESIZE - 1])
	)
	# NOTE(tori): find information in packet(7) as `struct sockaddr_ll`
	packed = ifreq[18:24]

	return packed

def list_ifaces():
	return __import__('os').listdir('/sys/class/net')

def broadcast_listen(target_address, target_port, target_type,
	target_family=None, interface=None):
	socket = __import__('socket')
	addrinfos = socket.getaddrinfo(target_address, target_port)
	for addrinfo in addrinfos:
		family, type_, proto, canonname, sockaddr = addrinfo
		if ((family == target_family or target_family is None)
			and (type_ == target_type)):
			sock = socket.socket(family, type_, proto)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			if interface is not None:
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
					interface + b'\0')
			sock.bind((target_address, target_port))
			return sock
	else:
		raise Exception('could not listen')

def multicast_listen(target_address, target_port, target_type,
	target_family=None, bind_address=None):
	socket = __import__('socket')
	struct = __import__('struct')
	addrinfos = socket.getaddrinfo(target_address, target_port)
	for addrinfo in addrinfos:
		family, type_, proto, canonname, sockaddr = addrinfo
		if ((family == target_family or target_family is None)
			and (type_ == target_type)):
			sock = socket.socket(family, type_, proto)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			if bind_address is None:
				bind_address = ''
			sock.bind((bind_address, target_port))
			group = socket.inet_pton(family, sockaddr[0])
			if family == socket.AF_INET:
				request = group + struct.pack('=I', socket.INADDR_ANY)
				sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
					request)
			elif family == socket.AF_INET6:
				request = group + struct.pack('@I', 0)
				sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
					request)
			else:
				raise Exception('bad address family')
			return sock
	else:
		raise Exception('could not listen')

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
