import unittest
from sullied_cryptography_testing import gmpwrapper

class TestGMPWrapper(unittest.TestCase):
	"""
	Test libgmp wrapper.
	"""
	def test_cube_root(self):
		self.assertEqual(gmpwrapper.integer_cube_root(27), 3)
