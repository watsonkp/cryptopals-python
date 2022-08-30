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
