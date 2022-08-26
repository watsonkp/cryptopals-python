import hashlib
import json
import secrets
from sullied_cryptography_testing import diffiehellman
from sullied_cryptography_testing import srp
from sullied_cryptography_testing.cryptowrapper import sha256
from sullied_cryptography_testing.digest import hmac_sha256
from sullied_cryptography_testing import util

# RFC 5054
# https://tools.ietf/org/html/rfc5054

class Client():
	def __init__(self, server, N, g, k):
		self.server = server
		self.N = N
		self.g = g
		self.k = k
		self.private_key, self.public_key = diffiehellman.getKeyPair(self.N, self.g)

	def authenticate(self, email, password):
		message = json.dumps({'email': email, 'A': self.public_key})
		print('Client -> Server')
		print(message)
		response = self.server.getResponse(message)
		server_hello = json.loads(response)

		u_h = sha256(str(self.public_key + server_hello['B']).encode('utf-8'))
		u = int(''.join(['{:02x}'.format(b) for b in u_h]), 16)

		x_h = sha256((str(server_hello['salt']) + password).encode('utf-8'))
		x = int(''.join(['{:02x}'.format(b) for b in x_h]), 16)

		# Calculate the shared secret
		# S = (B - k * g ^ x)^(a + u * x) % N
		# Naive implementation that is too slow (have never let it run to completion)
		# because of the exponentiation without a modulus
		# S = pow(server_hello['B'] - self.k * self.g ** x, self.private_key + u * x, self.N)
		# Using (a^b) mod c=((a mod c)^b)mod c
		# S = ((B - k * g ^ x) % N)^(a + u * x) % N
		# I think the rest of this is intuitively ok. Adding an extra mod N earlier in
		# the computation seems safe for a lot of operations.
		# S = (B - (k * g ^ x) % N)^(a + u * x) % N
		# S = (B - k * ((g ^ x) % N))^(a + u * x) % N
		S = pow(server_hello['B'] - self.k * pow(self.g, x, self.N), self.private_key + u * x, self.N)
		K = sha256(str(S).encode('utf-8'))

		digest = hmac_sha256(K, str(server_hello['salt']).encode('utf-8'))
		message = json.dumps({'email': email, 'mac': ''.join(['{:02x}'.format(b) for b in digest])})
		print('Client -> Server')
		print(message)
		response = self.server.getResponse(message)
		authenticated = json.loads(response)
		if authenticated['authenticated'] == 'True':
			return True
	
		return False

class MaliciousClient():
	def __init__(self, server):
		self.server = server
		self.session_key = sha256(str(0).encode('utf-8'))

	def authenticate(self, email, public_key):
		message = json.dumps({'email': email, 'A': public_key})
		print('Client -> Server')
		print(message)
		response = self.server.getResponse(message)
		salt = json.loads(response)['salt']

		digest = hmac_sha256(self.session_key, str(salt).encode('utf-8'))
		message = json.dumps({'email': email, 'mac': ''.join(['{:02x}'.format(b) for b in digest])})
		print('Client <- Server')
		print(message)
		response = self.server.getResponse(message)
		authenticated = json.loads(response)
		if authenticated['authenticated'] == 'True':
			return True
	
		return False

class Session():
	def __init__(self, N, g, k, identity, client_public_key):
		self.N = N
		self.g = g
		self.k = k
		self.identity = identity

		self.private_key = secrets.randbits(2048) % self.N
		self.public_key = self.k * self.identity['v'] + pow(self.g, self.private_key, self.N)

		u_h = sha256(str(client_public_key + self.public_key).encode('utf-8'))
		u = int(''.join(['{:02x}'.format(b) for b in u_h]), 16)

		# Calculating shared secret
		# S = (A * v^u)^b % N
		# Using a^b mod c = (a mod c)^b mod c
		# S = ((A * v^u) % N)^b % N
		# S = (A * (v^u % N))^b % N
		S = pow(client_public_key * pow(identity['v'], u, self.N), self.private_key, self.N)
		
		self.K = sha256(str(S).encode('utf-8'))

	def validate(self, digest):
		server_digest = hmac_sha256(self.K, str(self.identity['salt']).encode('utf-8'))
		server_hex_digest = ''.join(['{:02x}'.format(b) for b in server_digest])
		if server_hex_digest == digest:
			return True
		return False

class Server():
	def __init__(self, N, g, k):
		self.N = N
		self.g = g
		self.k = k
		self.identities = {}
		self.createSession = lambda identity, public_key: Session(self.N, self.g, self.k, identity, public_key)

	def addUser(self, email, password):
		salt = secrets.randbits(2048)
		x_h = sha256((str(salt) + password).encode('utf-8'))
		x = int(''.join(['{:02x}'.format(b) for b in x_h]), 16)
		self.identities[email] = {'salt': salt, 'v': pow(self.g, x, self.N)}
		print('Added user: {}'.format(email))

	def getResponse(self, request):
		message = json.loads(request)
		# Handle client hello
		if 'email' in message and 'A' in message:
			user = self.identities[message['email']]

			# Create ephemeral authentication session
			session = self.createSession(user, message['A'])
			print('Created session')
			# Store ephemeral authentication session
			self.identities[message['email']]['session'] = session

			response = json.dumps({'salt': user['salt'], 'B': session.public_key})

			print('Server -> Client')
			print(response)
			return response
		# Validate client credential
		elif 'email' in message and 'mac' in message:
			user = self.identities[message['email']]
			session = user['session']
			if session.validate(message['mac']):
				response = json.dumps({'authenticated': 'True'})
			else:
				response = json.dumps({'authenticated': 'False'})
			print('Server -> Client')
			print(response)
			return response
		else:
			raise ValueError('Unexpected request content: {}'.format(message))

class SimpleCredential():
	g = 2
	N = diffiehellman.RFC3526_1536_p
	def __init__(self, password):
		# x = SHA256(salt|password)
		# v = g**x % n
		self.salt = secrets.token_bytes(16)
		m = hashlib.sha256()
		m.update(self.salt + password.encode('utf-8'))
		x = util.bytesToInt(m.digest())
		self.v = pow(self.g, x, mod=self.N)

class SimpleClient():
	g = 2
	N = diffiehellman.RFC3526_1536_p

	def authenticate(self, server, email, password):
		# A = g**a % n
		a = secrets.randbits(128)
		A = pow(self.g, a, mod=self.N)
		salt, B, u = server.negotiate(email, A)

		# x = SHA256(salt|password)
		m = hashlib.sha256()
		m.update(salt + password.encode('utf-8'))
		x = util.bytesToInt(m.digest())
		# S = B**(a + ux) % n
		S = pow(B, a + u * x, mod=self.N)
		# K = SHA256(S)
		m = hashlib.sha256()
		m.update(S.to_bytes(192, 'little'))
		K = m.digest()

		# Send HMAC-SHA256(K, salt)
		return server.authenticate(hmac_sha256(salt, K))

class SimpleServer():
	g = 2
	N = diffiehellman.RFC3526_1536_p

	def __init__(self, email, password):
		self.credentials = {email: SimpleCredential(password)}

	def negotiate(self, I, A):
		self.A = A
		self.I = I
		# B = g**b % n, u = 128 bit random number
		self.b = secrets.randbits(128)
		B = pow(self.g, self.b, mod=self.N)
		self.u = secrets.randbits(128)
		return self.credentials[self.I].salt, B, self.u

	def authenticate(self, token):
		v = self.credentials[self.I].v
		salt = self.credentials[self.I].salt
		# S = (A * v ** u)**b % n
		S = pow(self.A * pow(v, self.u, mod=self.N), self.b, mod=self.N)
		# K = SHA256(S)
		m = hashlib.sha256()
		m.update(S.to_bytes(192, 'little'))
		K = m.digest()
		# Send "OK" if HMAC-SHA256(K, salt) validates
		return hmac_sha256(salt, K) == token

class SimpleMITM():
	g = 2
	N = diffiehellman.RFC3526_1536_p

	def __init__(self, wordlist):
		self.wordlist = wordlist
		self.salt = secrets.token_bytes(16)

	def negotiate(self, I, A):
		self.A = A
		self.b = secrets.randbits(128)
		B = pow(self.g, self.b, mod=self.N)
		self.u = secrets.randbits(128)
		return self.salt, B, self.u

	def authenticate(self, token):
		for word in self.wordlist:
			if self.guess(token, word):
				print('Found password: ' + word)
				return True
		return False

	def guess(self, token, password):
		m = hashlib.sha256()
		m.update(self.salt + password.encode('utf-8'))
		x = util.bytesToInt(m.digest())
		v = pow(self.g, x, mod=self.N)
		S = pow(self.A * pow(v, self.u, mod=self.N), self.b, mod=self.N)
		m = hashlib.sha256()
		m.update(S.to_bytes(192, 'little'))
		K = m.digest()
		return hmac_sha256(self.salt, K) == token
