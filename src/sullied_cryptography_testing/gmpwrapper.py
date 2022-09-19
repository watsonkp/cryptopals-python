from ctypes import *

GMP_WRAPPER = cdll.LoadLibrary("libgmpwrapper-0.1.0.so")

class MathException(Exception):
	"""
	Represents errors returned from GMP.
	"""
	pass

def integer_cube_root(x):
	"""
	:param x: The number for which to calculate the cube root.
        :type x: int
        :raises MathException: Raised when the root is not an exact integer.
        :return: The integer cube root.
        :rtype: int
        """
	bs = x.to_bytes((x.bit_length() + 7) // 8, 'little')
	root_buffer = c_void_p(None)
	root_buffer_length = c_size_t(0)

	# Call the C wrapper function around the mpz_root function of libgmp.
	GMP_WRAPPER.integer_cube_root.argtypes = [c_void_p, c_size_t, POINTER(c_void_p), POINTER(c_size_t)]
	GMP_WRAPPER.integer_cube_root.restype = c_int
	if 0 == GMP_WRAPPER.integer_cube_root(bs, len(bs), byref(root_buffer), byref(root_buffer_length)):
		raise MathException("Root is not an exact integer value.")

	# Read and decode the root value from the buffer using the returned length.
	root_bs = string_at(root_buffer, root_buffer_length.value)
	return int.from_bytes(root_bs, 'little')
