def invmod(y, n):
	"""
	Computes the modular multiplicative inverse such that y % n * invmod(y, n) = 1. If there is no inverse None is returned.
	:param y: The numerator.
	:type y: int
	:param n: The modulus.
	:type n: int
	:return: The modular multiplicative inverse.
	:rtype: int
	"""
	a, b, d = bezout(y, n)
	if d != 1:
		return None
	inverse = a if a > 0 else a + n
	return inverse

def gcd(x, y):
	"""
	Computes the greatest common divisor of two positive integers with Euclid's algorithm.
	Euclid's Algorithm specified by Knuth in The Art of Computer Programming Volume 1 Page 2.
	:param x: The first positive integer.
	:type x: int
	:param y: The second positive integer.
	:type y: int
	:return: The greatest common divisor.
	:rtype: int or None
	"""
	m = x if x > y else y
	n = y if m == x else x

	while True:
		quotient = m // n
		remainder = m - quotient * n
		if remainder == 0:
			return n
		m = n
		n = remainder

def bezout(x, y):
	"""
	Computes the greatest common divisor of two positive integers as well as a and b such that ax + by = gcd(x, y), Bézout's identity, with Euclid's extended algorithm.
	Euclid's Algorithm specified by Knuth in The Art of Computer Programming Volume 1 Page 13.
	:param x: The first positive integer.
	:type x: int
	:param y: The second positive integer.
	:type y: int
	:return: The greatest common divisor.
	:rtype: (int, int, int)
	"""
	a_prime = 1
	b = 1
	a = 0
	b_prime = 0
	c = x
	d = y
	while True:
		quotient = c // d
		remainder = c - quotient * d
		if remainder == 0:
			return (a, b, d)
		c = d
		d = remainder
		t = a_prime
		a_prime = a
		a = t - quotient * a
		t = b_prime
		b_prime = b
		b = t - quotient * b

def chinese_remainder_theorem(residue, modulus):
	"""
	Implementation of the Chinese Remainder Theorem for a 3 equation system.
	Discovered by Sun Tsǔ around 350 CE according to Concrete Mathetmatics by Graham, Knuth and Patashnik on page 126.
	:param residue: List of 3 integers each representing a unique residue.
        :type residue: [int]
	:param modulus: List of 3 integers each representing a unique modulus.
        :type modulus: [int]
        :raises ValueError: Raised when either residue or modulus does not contain 3 values.
        :return: The solution to the system of equations.
        :rtype: int
	"""
	if len(residue) != 3 or len(modulus) != 3:
		raise ValueError("Implementation can only handle systems of 3 equations. Residues: {} != 3 or Modulus: {} != 3".format(len(residue), len(modulus)))

	m_s_0 = modulus[1] * modulus[2]
	m_s_1 = modulus[0] * modulus[2]
	m_s_2 = modulus[0] * modulus[1]

	solution = residue[0] * m_s_0 * invmod(m_s_0, modulus[0])\
		+ residue[1] * m_s_1 * invmod(m_s_1, modulus[1])\
		+ residue[2] * m_s_2 * invmod(m_s_2, modulus[2])
	N = modulus[0] * modulus[1] * modulus[2]
	return solution % N
