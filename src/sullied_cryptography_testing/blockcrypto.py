import base64
from sullied_cryptography_testing import ciphers
from sullied_cryptography_testing import cryptowrapper

def challenge9():
	block = 'AAAABBBBCCCC'.encode('utf-8')
	return ciphers.padWithPKCS7(block, 16)

def challenge10():
	with open('./tests/data/10.txt') as f:
		ciphertext = base64.b64decode(f.read())

	iv = 16 * b'\x00'
	key = 'YELLOW SUBMARINE'.encode('utf-8')
	# TODO: AES-CBC-PKCS7 generator using a 1 block buffer to detect and unpad last block
	plaintext_blocks = [block for block in ciphers.decryptCBC(iv + ciphertext, lambda block: cryptowrapper.decryptAES(key, block, 128))]
	plaintext_blocks[-1] = ciphers.unpadWithPKCS7(plaintext_blocks[-1])
	return ''.join([block.decode('utf-8') for block in plaintext_blocks])
