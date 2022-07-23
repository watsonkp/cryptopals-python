import unittest
import ciphers
import cryptowrapper
from functools import reduce

class TestCiphers(unittest.TestCase):
	def test_cbcCrypt(self):
		key = 'YELLOW SUBMARINE'.encode('utf-8')
		message = 'AAAABBBBCCCCDDDDEEEE'.encode('utf-8')
		ciphertext = ciphers.encryptCBC(message,
						lambda block: cryptowrapper.encryptAES(key, block, 128))
		plaintext = ciphers.decryptCBC(reduce(lambda x, y: x + y, ciphertext),
						lambda block: cryptowrapper.decryptAES(key, block, 128))
		decrypted = reduce(lambda x, y: x + y, plaintext)
		decrypted = decrypted[:-16] + ciphers.unpadWithPKCS7(decrypted[-16:])
		self.assertEqual(decrypted, message)
