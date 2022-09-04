from sullied_cryptography_testing import cryptowrapper
from sullied_cryptography_testing import numbertheory
from sullied_cryptography_testing import util

class PublicKey:
	def __init__(self, e, p=None, q=None):
		"""Create RSA public key
		:param e: Public exponent. A small odd value.
		:type e: int
		:param p: Random prime integer.
		:type p: int
		:param q: Random prime integer.
		:type q: int
		"""
		if p == None and q == None:
			p = cryptowrapper.generatePrime(1024)
			q = cryptowrapper.generatePrime(1024)
		self.e = e
		self.n = p * q

class PrivateKey:
	def __init__(self, e, p, q):
		"""Create RSA private key
		:param e: Public exponent. A small odd value.
		:type e: int
		:param p: Random prime integer.
		:type p: int
		:param q: Random prime integer.
		:type q: int
		"""

		n = p * q
		# totient
		e_t = (p - 1) * (q - 1)
		d = numbertheory.invmod(e, e_t)
		if d == None:
			print('d is None')
		self.d = d
		self.n = n

class Peer:
	def __init__(self, e=3):
		"""Create RSA peer with public/private key-pair.
		:param e: Public exponent. A small odd value.
		:type e: int
		"""
		p = cryptowrapper.generatePrime(1024)
		q = cryptowrapper.generatePrime(1024)
		self.public_key = PublicKey(e, p, q)
		self.private_key = PrivateKey(e, p, q)

	def encrypt(self, message, public_key=None):
		"""Encrypt a message using the public key.
		:param message: Message to encrypt.
		:type message: int, string or bytes
		:return: Encrypted message as an integer.
		:rtype: int
		"""
		if isinstance(message, str):
			message = util.bytes_to_int(message.encode('utf-8'))
		elif isinstance(message, bytes):
			message = util.bytes_to_int(message)

		if public_key != None:
			cipher_text = pow(message, public_key.e, mod=public_key.n)
		else:
			cipher_text = pow(message, self.public_key.e, mod=self.public_key.n)
		return cipher_text

	def decrypt(self, ciphertext):
		"""Decrypt a message using the private key.
		:param ciphertext: Ciphertext to decrypt.
		:type ciphertext: int
		:return: Decrypted message as an integer.
		:rtype: int
		"""
		return pow(ciphertext, self.private_key.d, mod=self.private_key.n)
