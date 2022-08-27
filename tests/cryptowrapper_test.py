import unittest
from sullied_cryptography_testing import cryptowrapper

class TestCryptoWrapper(unittest.TestCase):
	"""
	Test prime number generation.
	"""
	# TODO: Check for variability
	# TODO: Check for primality
	def test_generate_prime(self):
		prime = cryptowrapper.generatePrime(8)
		# The only 8 bit prime with the top two bits set is 227
		self.assertEqual(227, prime)

	# TODO: Check larger primes. Fixed seed?
	def test_generate_prime_bigger(self):
		# Generate a bigger prime
		cryptowrapper.generatePrime(1024)
		self.assertTrue(True)
