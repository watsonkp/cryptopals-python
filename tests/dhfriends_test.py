import unittest
import secrets
from sullied_cryptography_testing import dhfriends
from sullied_cryptography_testing import srp
from sullied_cryptography_testing import diffiehellman as dh
from sullied_cryptography_testing import rsa
from sullied_cryptography_testing import util
from sullied_cryptography_testing import numbertheory
from sullied_cryptography_testing import gmpwrapper

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
		Rationale
		The simple SRP implementation server public key (B) does not depend on the password. When it does, the client produces a nonsensical token for incorrect password guesses. The server needs to repeatedly guess the password, have the client attempt an authentication, and then check the guess. Removing the dependence of the server public key on the password removes the need for repeated client authentication attempts.
		"""
		wordlist = ['123456', '12345', '123456789', 'password', 'iloveyou', 'princess', '1234567', 'rockyou', '12345678', 'abc123']
		email = 'user@example.com'
		password = secrets.choice(wordlist)

		server = srp.SimpleServer(email, password)
		client = srp.SimpleClient()
		# Authenticate to server with the correct email and password
		self.assertTrue(client.authenticate(server, email, password))

		# Fail to authenticate to server with the correct email and incorrect password
		self.assertFalse(client.authenticate(server, email, 'nonsense'))

		mitm_server = srp.SimpleMITM(wordlist)
		# Guess the password with brute force
		self.assertTrue(client.authenticate(mitm_server, email, password))
		# Fail to guess a password not included in the wordlist with brute force
		self.assertFalse(client.authenticate(mitm_server, email, 'nonsense'))
	def test_challenge39(self):
		"""
		Implement RSA.
		"""
		peer = rsa.Peer()

		# Encrypt and decrypt a simple integer message
		message = 42
		ciphertext = peer.encrypt(message)
		plaintext = peer.decrypt(ciphertext)
		self.assertEqual(message, plaintext)

		# Encrypt and decrypt a string
		message = "The quick brown fox jumped over the lazy dog."
		ciphertext = peer.encrypt(message)
		plaintext = util.int_to_bytes(peer.decrypt(ciphertext)).decode('utf-8')
		self.assertEqual(message, plaintext)

		# Encrypt and decrypt bytes
		message = b'\xab\ad\x1d\xea'
		ciphertext = peer.encrypt(message)
		plaintext = util.int_to_bytes(peer.decrypt(ciphertext))
		self.assertEqual(message, plaintext)

	def test_challenge40(self):
		"""
		Implement an E=3 RSA Broadcast attack.
		The attacker observes the same message encrypted 3 times with 3 distinct public keys and is able to decrypt the message without knowledge of the private key. The length of the message that can be decrypted is limited by E. Larger values for E lower this limit so that it is not useful.
		"""
		peer = rsa.Peer()

		message = "The quick brown fox jumped over the lazy dog."
		e = 3

		# Encrypt the same message with 3 different public keys.
		public_key_1 = rsa.PublicKey(e)
		cipher_text_1 = peer.encrypt(message, public_key=public_key_1)
		public_key_2 = rsa.PublicKey(e)
		cipher_text_2 = peer.encrypt(message, public_key=public_key_2)
		public_key_3 = rsa.PublicKey(e)
		cipher_text_3 = peer.encrypt(message, public_key=public_key_3)

		# Retrieve the message from the cube root of the result of the Chinese Remainder Theorem.
		residues = [cipher_text_1, cipher_text_2, cipher_text_3]
		modulus = [public_key_1.n, public_key_2.n, public_key_3.n]
		sum = numbertheory.chinese_remainder_theorem(residues, modulus)
		plain_text = util.int_to_bytes(gmpwrapper.integer_cube_root(sum))
		self.assertEqual(plain_text.decode('utf-8'), message)
