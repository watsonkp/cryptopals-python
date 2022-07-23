from functools import reduce
import ciphers
import string
import secrets

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
