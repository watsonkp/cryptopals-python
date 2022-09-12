import unittest
import datetime
import secrets
from sullied_cryptography_testing import numbertheory
from sullied_cryptography_testing import rsa
from sullied_cryptography_testing import util

class TestRSAAndDSA(unittest.TestCase):
	def test_challenge41(self):
		"""
		Implement unpadded message recovery oracle

		The server will decrypt and return arbitrary RSA blobs submitted to it. The server will not accept the same message twice.

		Messages include a timestamp so that clients can send the same message content repeatedly with unique RSA blobs.

		The goal is to capture other user's messages and use the server to decrypt them.
		"""

		message = '{{timestamp: {}, body: "{}"}}'.format(datetime.datetime.utcnow().isoformat(), "hi mom")
		oracle = rsa.Oracle()
		N = oracle.public_key.n
		E = oracle.public_key.e

		# Capture an encrypted message
		ciphertext = oracle.encrypt(message)

		# Decrypt the message once. Throw away the result.
		oracle.decrypt(ciphertext)

		# Decrypt the message again and the server rejects the attempt.
		self.assertEqual(None, oracle.decrypt(ciphertext))

		# Decrypt the product of the encrypted message and a random number.
		S = secrets.randbelow(N)
		C_prime = pow(S, E, mod=N) * ciphertext % N
		P_prime = oracle.decrypt(C_prime)

		# Calculate the modular inverse of the random number and use it to cancel the factor out of the plaintext.
		S_inv = numbertheory.invmod(S, N)
		plaintext = P_prime * S_inv % N

		# Calculated plaintext matches the submitted message.
		self.assertEqual(message, util.int_to_bytes(plaintext).decode('utf-8'))
