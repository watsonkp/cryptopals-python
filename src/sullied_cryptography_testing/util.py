import string
import secrets
from functools import reduce
from sullied_cryptography_testing import ciphers

def printHex(bs):
	print(' '.join(['{:02x}'.format(b) for b in bs]))

def xor(a, b):
	return bytes([x^y for x,y in zip(a, b)])

def flattenAndUnpad(blocks):
	accumulated = reduce(lambda x,y: x+y, blocks)
	return accumulated[:-16] + ciphers.unpadWithPKCS7(accumulated[-16:])

def printable(s):
	for c in s:
		if c not in string.printable:
			return False
	return True

def generateRandomPasswords(n):
	return [secrets.token_hex(32) for _ in range(n)]

def bytesToInt(bs):
	return int('0x' + ''.join(['{:02x}'.format(b) for b in bs]), 16)

def bytes_to_int(bs):
	"""
	Convert a bytes value to an integer representation.
	:param bs: Bytes value to convert.
	:type bs: int
	:return: Integer representation.
	:rtype: int
	"""
	return int.from_bytes(bs, 'big')

def int_to_bytes(x):
	"""
	Convert an integer value to a bytes representation.
	:param x: Integer value to convert.
	:type x: int
	:return: Bytes representation.
	:rtype: bytes
	"""
	return x.to_bytes((x.bit_length() + 7) // 8, 'big')
