import secrets
from sullied_cryptography_testing import util

def decryptECB(data, decrypt_fn):
	blocks = [data[i:i+16] for i in range(0, len(data), 16)]
	#return ''.join([decryptAES("YELLOW SUBMARINE".encode('utf-8'), block, 128).decode('utf-8') for block in blocks])
	return ''.join([decrypt_fn(block).decode('utf-8') for block in blocks])

def xorBlock(x, y):
	return bytes([a ^ b for a, b in zip(x, y)])

def getBlocks(data, n):
	for i in range(0, len(data), n):
		yield data[i:i+16]

def decryptCBC(data, decrypt_fn):
	blocks = getBlocks(data, 16)
	# Get the IV as a prefix
	previous = next(blocks)
	for block in blocks:
		yield xorBlock(previous, decrypt_fn(block))
		previous = block

def encryptCBC(data, encrypt_fn):
	data = padWithPKCS7(data, 16)
	blocks = getBlocks(data, 16)
	iv = secrets.token_bytes(16)
	yield iv

	previous = iv
	for block in blocks:
		cipherblock = encrypt_fn(xorBlock(previous, block))
		previous = cipherblock
		yield cipherblock

def padWithPKCS7(data, k):
	"""tools.ietf.org/html/rfc2315
	For blocksize k and data length l.
	Pad with k - (l mod k) using value k - (l mod k)
	"""
	n = k - (len(data) % k)
	return data + (n * n.to_bytes(1, 'little'))

def unpadWithPKCS7(block):
	n = block[-1]
	for i in range(-1, -(n+1), -1):
		if block[i] != n:
			raise ValueError('Padding is not valid PKCS#7: {}'.format(' '.join(['{:02x}'.format(b) for b in block])))

	return block[:len(block)-n]
