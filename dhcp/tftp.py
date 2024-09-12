# SPDX-License-Identifier: MIT

# NOTE(tori): compliant with RFCs 1350, 1782-1784, 7440(verify)

import argparse
import codecs
import logging
import socket
import threading
import typing
from dataclasses import dataclass
from errno import ENOSPC
from ipaddress import IPv4Address
from pathlib import Path
from struct import Struct, error as StructError
from sys import stderr
try:
	import enum
except ImportError:
	class enum:
		Enum = object
		IntEnum = object
		IntFlag = object
		Flag = object

		def unique(method):
			return method

		def auto(method):
			return 1/0
	enum = enum()

_netascii_encode_table = {
	**{chr(value): bytes([value]) for value in range(0x20, 0x7F)},
	'\x7F': bytes([0x7F]),
	'\0': bytes([0x00]),
	'\n': bytes([0x0D, 0x0A]),
	'\r': bytes([0x0D, 0x00]),
	'\a': bytes([0x07]),
	'\x08': bytes([0x08]),
	'\x09': bytes([0x09]),
	'\x0B': bytes([0x0B]),
	'\x0C': bytes([0x0C])
}
_netascii_decode_table = {
	v: k for k, v in _netascii_encode_table.items()
}

_netascii_codec_name = 'netascii'


class NetASCIIEncodeError(ValueError):
	pass


class NetASCIIDecodeError(ValueError):
	pass


def _netascii_encode(s):
	try:
		return b''.join(_netascii_encode_table[c] for c in s), len(s)
	except KeyError as e:
		key, = e.args
		idx = s.index(key)
		raise NetASCIIEncodeError(
			'%r codec can\'t encode character %r at position %r: %s'
			% (_netascii_codec_name, key, idx, 'Invalid Character')
		) from None


def _netascii_decode(b):
	result = []
	accumulator = b''
	try:
		for index, byte in enumerate(b):
			accumulator += bytes([byte])
			if accumulator in _netascii_decode_table:
				result.append(_netascii_decode_table[accumulator])
				accumulator = b''
			if len(accumulator) > 2:
				key = accumulator
				idx = index - len(accumulator)
				raise NetASCIIDecodeError(
					'%r codec can\'t decode bytes %r at position %r: %s'
					% (_netascii_codec_name, key, idx, 'Invalid Byte Sequence')
				) from None
		if accumulator:
			key = accumulator
			idx = index - len(accumulator)
			raise NetASCIIDecodeError(
				'%r codec can\'t decode bytes %r at position %r: %s'
				% (_netascii_codec_name, key, idx, 'Invalid Byte Sequence')
			) from None
	except Exception as e:
		raise e
	return ''.join(result), len(b)


def _netascii_search_function(encoding_name):
	return codecs.CodecInfo(_netascii_encode, _netascii_decode,
		name=_netascii_codec_name)


codecs.register(_netascii_search_function)


class Error(Exception):
	pass


class MalformedPacketError(Error):
	pass


class Operation(enum.IntEnum):
	READ_REQUEST = 1
	RRQ = 1
	WRITE_REQUEST = 2
	WRQ = 2
	DATA = 3
	ACKNOWLEDGEMENT = 4
	ACK = 4
	ERROR = 5
	OPTION_ACKNOWLEDGEMENT = 6
	OACK = 6


class Error(enum.IntEnum):
	UNDEFINED = 0
	FILE_NOT_FOUND = 1
	ACCESS_VIOLATION = 2
	DISK_FULL = 3
	ILLEGAL_OPERATION = 4
	UNKNOWN_TRANSFER_ID = 5
	FILE_EXISTS = 6
	NO_SUCH_USER = 7
	UNSUPPORTED_OPTIONS = 8


SHORT = Struct('!H')


class BasePacket:
	pass


@dataclass
class ReadPacket(BasePacket):
	filename: str
	transfer_mode: str
	options: list


@dataclass
class WritePacket(BasePacket):
	filename: str
	transfer_mode: str
	options: list


@dataclass
class DataPacket(BasePacket):
	block_number: int
	data: bytes


@dataclass
class AckPacket(BasePacket):
	block_number: int


@dataclass
class ErrorPacket(BasePacket):
	error_code: Error
	error_message: str


@dataclass
class OptionAckPacket(BasePacket):
	options: list


def decode_short(pkt):
	try:
		value, = SHORT.unpack_from(pkt)
		pkt = pkt[SHORT.size:]
	except Exception:
		raise MalformedPacketError('invalid short') from None
	return value, pkt


def decode_string(pkt):
	try:
		string = pkt[:pkt.index(b'\0')].decode('netascii')
		remainder = pkt[len(string) + 1:]
	except (ValueError, NetASCIIDecodeError):
		raise MalformedPacketError('invalid string') from None
	return string, remainder


def decode_options(pkt):
	options = []

	while pkt:
		name, pkt = decode_string(pkt)
		value, pkt = decode_string(pkt)
		options.append((name, value))

	return options


def decode_packet(pkt: bytes) -> BasePacket:
	operation, pkt = decode_short(pkt)
	op = Operation(operation)

	if op == Operation.READ_REQUEST or op == Operation.WRITE_REQUEST:
		filename, pkt = decode_string(pkt)
		mode, pkt = decode_string(pkt)
		options = decode_options(pkt)

		cls = ReadPacket if op == Operation.READ_REQUEST else WritePacket
		return cls(filename, mode, options)
	elif op == Operation.DATA:
		block_number, pkt = decode_short(pkt)
		data = pkt

		return DataPacket(block_number, data)
	elif op == Operation.ACKNOWLEDGEMENT:
		block_number, pkt = decode_short(pkt)

		if pkt:
			raise MalformedPacketError()

		return AckPacket(block_number)
	elif op == Operation.ERROR:
		error_code, pkt = decode_short(pkt)
		error_message, pkt = decode_string(pkt)

		if pkt:
			raise MalformedPacketError()

		return ErrorPacket(Error(error_code), error_message)
	elif op == Operation.OPTION_ACKNOWLEDGEMENT:
		options = decode_options(pkt)
		return OptionAckPacket(options)
	else:
		raise Error('unimplemented operation: %r' % op)


def encode_short(value, pkt=b''):
	try:
		return pkt + SHORT.pack(value)
	except StructError:
		raise ValueError('invalid value: %r' % value)


def encode_string(string, pkt=b''):
	try:
		return pkt + string.encode('netascii') + b'\0'
	except NetASCIIEncodeError:
		raise ValueError('invalid string: %r' % string)


def encode_options(options, pkt=b''):
	for key, value in options:
		pkt = encode_string(key, pkt)
		pkt = encode_string(value, pkt)
	return pkt


def encode_packet(pkt: BasePacket) -> bytes:
	if isinstance(pkt, (ReadPacket, WritePacket)):
		operation = (Operation.READ_REQUEST if isinstance(pkt, ReadPacket)
			else Operation.WRITE_REQUEST)
		result = encode_short(operation)
		result = encode_string(pkt.filename, result)
		result = encode_string(pkt.transfer_mode, result)
		result = encode_options(pkt.options, result)
		return result
	elif isinstance(pkt, DataPacket):
		result = encode_short(Operation.DATA)
		result = encode_short(pkt.block_number, result)
		result += pkt.data
		return result
	elif isinstance(pkt, AckPacket):
		result = encode_short(Operation.ACKNOWLEDGEMENT)
		result = encode_short(pkt.block_number)
		return result
	elif isinstance(pkt, ErrorPacket):
		result = encode_short(Operation.ERROR)
		result = encode_short(pkt.error_code, result)
		result = encode_string(pkt.error_message, result)
		return result
	elif isinstance(pkt, OptionAckPacket):
		result = encode_short(Operation.OPTION_ACKNOWLEDGEMENT)
		result = encode_options(pkt.options, result)
		return result
	else:
		raise Error('unimplemented packet type: %r' % pkt)


def folder_manager(folder=Path.cwd()):
	folder = Path(folder)

	def opener(name, mode):
		name = Path(name)
		if name.is_absolute():
			name = name.relative_to('/')
		target = folder/name
		if not target.resolve().is_relative_to(folder.resolve()):
			raise Exception('access violation')
		return open(target, mode)

	def sizer(name):
		name = Path(name)
		if name.is_absolute():
			name = name.relative_to('/')
		target = folder/name
		if not target.resolve().is_relative_to(folder.resolve()):
			raise Exception('access violation')
		return target.stat().st_size
	return opener, sizer


# NOTE(tori): we're not using socketserver because I want more control over
# stuff about my server
class Server:
	def __init__(self, logger, filemanager, ip='0.0.0.0', port=69):
		self.logger = logger
		self.open, self.size = filemanager
		self.ip = ip
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.socket.bind((str(self.ip), port))
		self.socket.settimeout(5)
		self.locks = {}
		self.threads = []
		self.logger.info(f'bound to {(str(ip), port)}')

	@staticmethod
	def send_error(socket, address, error, message=None):
		if message is None:
			message = {
				Error.UNDEFINED: 'no message provided',
				Error.FILE_NOT_FOUND: 'file not found',
				Error.ACCESS_VIOLATION: 'access violation',
				Error.DISK_FULL: 'no space left on device',
				Error.ILLEGAL_OPERATION: 'illegal operation',
				Error.UNKNOWN_TRANSFER_ID: 'unknown transfer ID',
				Error.FILE_EXISTS: 'file already exists',
				Error.NO_SUCH_USER: 'no such user'
			}.get(error, 'no such error: %r' % int(error))
		response = ErrorPacket(error, message)
		socket.sendto(encode_packet(response), address)

	@staticmethod
	def create_client_socket(ip):
		client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		client_socket.bind((str(ip), 0))
		client_socket.settimeout(10)

		return client_socket

	def open_file(self, packet, mode, dest_socket, address):
		try:
			if packet.transfer_mode == 'netascii':
				return self.open(packet.filename, '%s' % mode,
					encoding='netascii')
			elif packet.transfer_mode == 'octet':
				return self.open(packet.filename, '%sb' % mode)
			else:
				self.send_error(dest_socket, address, Error.ILLEGAL_OPERATION,
					'no such transfer mode: %s' % packet.transfer_mode)
		except FileNotFoundError as e:
			self.logger.warning(e)
			self.send_error(dest_socket, address, Error.FILE_NOT_FOUND)
		except FileExistsError:
			self.send_error(dest_socket, address, Error.FILE_EXISTS)
		except Exception as e:
			self.logger.error(e)

	def handle_read(self, packet, address):
		client_socket = self.create_client_socket(self.ip)

		lock = self.locks.setdefault(packet.filename, threading.Lock())
		with lock:
			file = self.open_file(packet, 'r', client_socket, address)

			if file is None:
				return

			with file:
				block_number = 1
				block_size = 512
				window_size = 1

				if packet.options:
					response = OptionAckPacket([])
					for option, value in packet.options:
						if option == 'blksize':
							block_size = int(value)
							response.options.append((option, value))
						elif option == 'timeout':
							client_socket.settimeout(int(value))
							response.options.append((option, value))
						elif option == 'tsize':
							response.options.append((option,
								str(self.size(packet.filename))))
						elif option == 'windowsize':
							window_size = int(value)
							response.options.append((option, value))
						else:
							self.logger.warning(
								'unrecognized option: %s' % option)
					# XXX(tori): this doesn't work on VLAN+wifi adapter
					client_socket.sendto(encode_packet(response), address)

					try:
						packet = decode_packet(client_socket.recvfrom(65535)[0])
					except MalformedPacketError:
						self.send_error(client_socket, address,
							Error.ILLEGAL_OPERATION)
						return
					except socket.timeout:
						return
					if not isinstance(packet, AckPacket):
						self.send_error(client_socket, address,
							Error.ILLEGAL_OPERATION)
						return
					if packet.block_number != 0:
						# NOTE(tori): should we return after this?
						# it would very likely be invalid, or not
						# I'm a comment, not a cop
						self.logger.warning('invalid block number: %r'
							% packet.block_number)

				while True:
					for _ in range(window_size):
						data = file.read(block_size)
						response = DataPacket(block_number, data)
						client_socket.sendto(encode_packet(response), address)
						# NOTE(tori): allow block overflow
						# block_number = (block_number + 1)%65536 or 1
						# NOTE(tori): the above does not seem to work for GRUB
						block_number = (block_number + 1)%65536
						if len(data) < block_size:
							break
					try:
						packet = decode_packet(client_socket.recvfrom(65535)[0])
					except MalformedPacketError:
						self.logger.error(
							'%r malformed packet from client' % (address,))
						return
					except socket.timeout:
						self.logger.warning('%r timeout' % (address,))
						return
					if isinstance(packet, AckPacket):
						if packet.block_number == (block_number - 1)%65536:
							self.logger.debug('ACK: %r' % packet.block_number)
						else:
							self.logger.warning('bad ACK: %r, [%r]'
								% (packet.block_number, block_number))
					elif isinstance(packet, ErrorPacket):
						self.logger.warning('%r error[%r]: %s'
							% (address, packet.error_code,
								packet.error_message))
						return
					else:
						self.send_error(client_socket, address,
							Error.ILLEGAL_OPERATION)
						return
					if len(packet.data) < block_size:
						break

	def handle_write(self, packet, address):
		client_socket = self.create_client_socket(self.ip)

		lock = self.locks.setdefault(packet.filename, threading.Lock())
		with lock:
			file = self.open_file(packet, 'x', client_socket, address)

			if file is None:
				return

			with file:
				expected_size = None
				block_size = 512
				received_size = 0

				if packet.options:
					response = OptionAckPacket([])
					for option, value in packet.options:
						if option == 'blksize':
							block_size = int(value)
							response.options.append((option, value))
						elif option == 'timeout':
							client_socket.settimeout(int(value))
							response.options.append((option, value))
						elif option == 'tsize':
							expected_size = int(value)
							response.options.append((option, value))
						else:
							self.logger.warning(
								'unrecognized option: %s' % option)
					client_socket.sendto(encode_packet(response), address)
				else:
					response = AckPacket(0)
					client_socket.sendto(encode_packet(response), address)

				while True:
					try:
						packet = decode_packet(
							client_socket.recvfrom(65535)[0])
					except socket.timeout:
						return
					if not isinstance(packet, DataPacket):
						self.send_error(client_socket, address,
							Error.ILLEGAL_OPERATION)
						return
					# NOTE(tori): I feel like there's an error here by not
					# writing the raw netascii to the file relating to some
					# multibyte character haberdashery, e.g. \r\0 or \r\n
					try:
						received_size += file.write(
							packet.data.decode('netascii'))
					except OSError as e:
						if e.errno == ENOSPC:
							self.send_error(client_socket, address,
								Error.DISK_FULL)
						else:
							self.send_error(client_socket, address,
								Error.UNDEFINED, e.strerror)
						return
					response = AckPacket(packet.block_number)
					client_socket.sendto(encode_packet(response), address)
					if len(packet.data) < block_size:
						break
				if expected_size is not None:
					if received_size != expected_size:
						self.logger.error('expected %r, got %r' % (
							expected_size, received_size))
						return

	def reap_threads(self):
		for thread in self.threads:
			if not thread.is_alive():
				self.threads.remove(thread)

	def wait_until_finished(self):
		for thread in self.threads:
			thread.join()
			self.threads.remove(thread)

	def accept(self):
		self.reap_threads()

		try:
			data, address = self.socket.recvfrom(65535)
			packet = decode_packet(data)
		except socket.timeout:
			return
		except Exception as e:
			self.logger.error(e)
			return

		handler = {
			ReadPacket: self.handle_read,
			WritePacket: self.handle_write,
		}.get(type(packet))

		if handler is not None:
			op = 'read from' if isinstance(packet, ReadPacket) else 'write to'
			self.logger.info('%r requesting to %s file %s'
				% (address, op, packet.filename))
			thread = threading.Thread(target=handler, args=(packet, address))
			thread.start()
			self.threads.append(thread)
		elif isinstance(packet, DataPacket):
			self.send_error(self.socket, address, Error.UNKNOWN_TRANSFER_ID)
		else:
			response = ErrorPacket(Error.ILLEGAL_OPERATION,
				'illegal TFTP operation')
			self.socket.sendto(encode_packet(response), address)
			self.logger.warning('unsolicited packet type: %r' % type(packet))

# def main():
# 	x = Server(folder_manager('./tftpboot'))
# 	while True:
# 		try:
# 			x.accept()
# 		except KeyboardInterrupt:
# 			break


def is_directory(f):
	f = Path(f)
	if f.is_dir():
		return f
	else:
		raise argparse.ArgumentTypeError('"%s" is not a valid directory' % f)


def configure_logging(output='-', level='INFO'):
	if isinstance(output, str):
		if output == '-':
			logging.basicConfig(stream=stderr)
		else:
			logging.basicConfig(filename=output)
	else:
		logging.basicConfig(stream=output)

	log_format = '{asctime}|{name}|{levelname}|{message}'
	log_formatter = logging.Formatter(log_format, style='{')

	log_handler = logging.StreamHandler()
	log_handler.setFormatter(log_formatter)

	logger = logging.Logger(__name__)
	logger.addHandler(log_handler)

	logger.setLevel(level)

	return logger


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--log-file', default='-',
		type=argparse.FileType('w'), help='location to log messages')
	parser.add_argument('-l', '--log-level', default='INFO', choices=('ALL',
		'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'), type=str.upper,
		help='verbosity of log messages, in descending order')
	parser.add_argument('-i', '--ip', metavar='IP', default='0.0.0.0',
		type=IPv4Address, help='IP address on which to bind')
	parser.add_argument('-p', '--port', metavar='PORT', default=69,
		type=int, help='port on which to bind')
	parser.add_argument('directory', metavar='DIR', default='./tftpboot',
		type=is_directory, help='directory from which to serve files')
	args = parser.parse_args()

	target = args.log_file
	level = 0 if args.log_level == 'ALL' else getattr(logging, args.log_level)
	logger = configure_logging(output=target, level=level)

	server = Server(logger, folder_manager(args.directory), ip=args.ip,
		port=args.port)
	while True:
		try:
			server.accept()
		except KeyboardInterrupt:
			server.wait_until_finished()
			break


if __name__ == '__main__':
	main()

# vim:set ft=python ts=4 sw=4 ai noet cc=80:
