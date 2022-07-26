import unittest
from sullied_cryptography_testing import numbertheory

class TestNumberTheory(unittest.TestCase):
	def test_gcd(self):
		"""
		Test the computation of the greatest common divisor.
		"""
		self.assertEqual(3, numbertheory.gcd(27, 33))
		self.assertEqual(21, numbertheory.gcd(1071, 462))

	def test_bezout(self):
		"""
		Test the computation of the greatest common divisor and Bezout's identity.
		"""
		self.assertEqual((5, -4, 3), numbertheory.bezout(27, 33))
		self.assertEqual((-8, 3, 1), numbertheory.bezout(7, 19))
		self.assertEqual((5, -16, 29), numbertheory.bezout(1769, 551))

	def test_invmod(self):
		"""
		Test the computation of the modular multiplicative inverse.
		"""
		self.assertEqual(11, numbertheory.invmod(7, 19))
		self.assertEqual(2753, numbertheory.invmod(17, 3120))

	def test_chinese_remainder_theorem(self):
		"""
		Test the use of the Chinese Remainder Theorem to solve a system of 3 equations.
		"""
		self.assertEqual(numbertheory.chinese_remainder_theorem([0, 3, 4], [3, 4, 5]), 39)
