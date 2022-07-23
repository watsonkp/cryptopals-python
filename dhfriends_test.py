import unittest
import dhfriends
import diffiehellman as dh
import secrets
import util

class TestDiffieHellmanAndFriends(unittest.TestCase):
	def test_challenge33(self):
		s1, s2 = dhfriends.challenge33(37, 5)
		self.assertEqual(s1, s2)

		s1, s2 = dhfriends.challenge33(dh.RFC3526_1536_p, dh.RFC3526_1536_g)
		self.assertEqual(s1, s2)

	def test_challenge34Echo(self):
		client_message = secrets.token_hex(20).encode('utf-8')
		self.assertEqual(dhfriends.challenge34Echo(client_message), client_message)

	def test_challenge34MITM(self):
		"""Replacing public keys with the constant p.
		Both client and server receive the modified public key.
		Client and server shared keys will match.
		"""
		client_message = secrets.token_hex(20).encode('utf-8')
		self.assertEqual(dhfriends.challenge34MITM(client_message), [('Client -> Server', client_message), ('Client <- Server', client_message)])

	def test_challenge35(self):
		"""Replacing the g parameter sent to the server with 1, p and p-1.
		The server's public key will cause the client to produce a predictable shared key.
		Client and server shared keys will not match.
		"""
		client_message = secrets.token_hex(20).encode('utf-8')
		self.assertEqual(dhfriends.challenge35(client_message, dh.RFC3526_1536_g, dh.RFC3526_1536_p, '1'),
			('Client -> Server', client_message))

		client_message = secrets.token_hex(20).encode('utf-8')
		self.assertEqual(dhfriends.challenge35(client_message, dh.RFC3526_1536_g, dh.RFC3526_1536_p, 'p'),
			('Client -> Server', client_message))

		client_message = secrets.token_hex(20).encode('utf-8')
		self.assertEqual(dhfriends.challenge35(client_message, dh.RFC3526_1536_g, dh.RFC3526_1536_p, 'p-1'),
			('Client -> Server', client_message))

	def test_challenge36(self):
		"""Implement Secure Remote Password (SRP)"""
		N = dh.RFC3526_1536_p
		g = 2
		k = 3
		email = 'user@example.com'
		password = secrets.token_hex(32)
	
		self.assertTrue(dhfriends.challenge36(N, g, k, email, password))

	def test_challenge37(self):
		"""Authenticate using malicious client public key and no password
		A=0, A=N, A=2*N"""
		N = dh.RFC3526_1536_p
		g = 2
		k = 3
		email = 'user@example.com'
		password = secrets.token_hex(32)
	
		self.assertTrue(dhfriends.challenge37(N, g, k, email, password, 0))
		self.assertTrue(dhfriends.challenge37(N, g, k, email, password, N))
		self.assertTrue(dhfriends.challenge37(N, g, k, email, password, 2 * N))

	def test_challenge38(self):
		"""Offline dictionary attack on simplified SRP
		PAKE algorithms are meant to prevent MITM attackers from offline brute force
		password guessing
		"""
		email = 'user@example.com'
		password_list = util.generateRandomPasswords(20)
	
		self.assertTrue(dh.challenge38(email, password_list))
