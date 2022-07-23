from cryptowrapper import sha256
from util import xor

# https://tools.ietf.org/html/rfc2104
def hmac_sha256(key, message):
	block_size = 64

	if len(key) > block_size:
		key = sha256(key)

	if len(key) < block_size:
		key = key + b'\x00' * (block_size - len(key))

	outer_pad = b'\x5c' * block_size
	inner_pad = b'\x36' * block_size

	return sha256(xor(key, outer_pad) + sha256(xor(key, inner_pad) + message))
