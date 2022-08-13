import json
import secrets
import base64
from functools import reduce
from sullied_cryptography_testing.diffiehellman import *
from sullied_cryptography_testing.cryptowrapper import encryptAES, decryptAES, sha1, sha256
from sullied_cryptography_testing import srp
from sullied_cryptography_testing import util
from sullied_cryptography_testing import ciphers

def challenge33(p, g):
	a, A = dh.getKeyPair(p, g)
	b, B = dh.getKeyPair(p, g)

	s1 = getSession(a, B, p)
	s2 = getSession(b, A, p)

	key_material = sha256(s1.to_bytes(1536>>3, 'little'))
	k1 = key_material[:int(len(key_material)/2)]
	k2 = key_material[int(len(key_material)/2):]

	return (s1, s2)

class EchoServer():
	def getResponse(self, message):
		message = json.loads(message)
		if 'p' in message and 'g' in message and 'A' in message:
			priv, pub = dh.getKeyPair(message['p'], message['g'])
			self.priv = priv
			self.pub = pub
			self.session = getSession(self.priv, message['A'], message['p'])
			#print('Server session:', self.session)
			return json.dumps({'B': self.pub})
		elif 'ciphertext' in message:
			shared_key = sha1(self.session.to_bytes(192, 'little'))[:16]
			plaintext_blocks = ciphers.decryptCBC(base64.b64decode(message['ciphertext']), lambda block: decryptAES(shared_key, block, 128))
			try:
				plaintext = util.flattenAndUnpad(plaintext_blocks)
			except ValueError as e:
				return json.dumps({'error': str(e)})
			return json.dumps({'ciphertext': base64.b64encode(reduce(lambda x,y: x+y, ciphers.encryptCBC(plaintext, lambda block: encryptAES(shared_key, block, 128)))).decode('utf-8')})
			
		else:
			raise ValueError('Unexpected request {}'.format(message))

class Client():
	def __init__(self, server):
		self.p = RFC3526_1536_p
		self.g = RFC3526_1536_g
		self.priv, self.pub = dh.getKeyPair(self.p, self.g)
		self.server = server

	def handshake(self):
		client_hello = {'p': self.p, 'g': self.g, 'A': self.pub}

#		print('Client -> Server\n{}'.format(client_hello))
		response = json.loads(self.server.getResponse(json.dumps(client_hello)))
#		print('Client <- Server\n{}'.format(response))

		self.session = getSession(self.priv, response['B'], self.p)

	def send(self, message):
		shared_key = sha1(self.session.to_bytes(192, 'little'))[:16]
		ciphertext = ciphers.encryptCBC(message, lambda block: encryptAES(shared_key, block, 128))

		request = {'ciphertext': base64.b64encode(reduce(lambda x,y: x+y, ciphertext)).decode('utf-8')}
#		print('Client -> Server\n{}'.format(request))
		response = json.loads(self.server.getResponse(json.dumps(request)))
		if 'error' in response:
			raise ValueError('Server error: {}'.format(response['error']))
#		print('Client <- Server\n{}'.format(response))
		return util.flattenAndUnpad(ciphers.decryptCBC(base64.b64decode(response['ciphertext']),
								lambda block: decryptAES(shared_key, block, 128)))

class MITMServer():
	def __init__(self, server):
		self.server = server
		self.log = []

	def getResponse(self, request):
		message = json.loads(request)
		if 'p' in message and 'g' in message and 'A' in message:
			p = message['p']
			message['A'] = p
			response = self.server.getResponse(json.dumps(message))

			message = json.loads(response)
			message['B'] = p
			return json.dumps(message)
		elif 'ciphertext' in request:
			session = 0
			message = base64.b64decode(json.loads(request)['ciphertext'])
			shared_key = sha1(session.to_bytes(192, 'little'))[:16]
			plaintext = util.flattenAndUnpad(ciphers.decryptCBC(message,
								lambda block: decryptAES(shared_key, block, 128)))
			self.log.append(('Client -> Server', plaintext))

			response = self.server.getResponse(request)
			message = base64.b64decode(json.loads(response)['ciphertext'])
			plaintext = util.flattenAndUnpad(ciphers.decryptCBC(message,
								lambda block: decryptAES(shared_key, block, 128)))
			self.log.append(('Client <- Server', plaintext))

			return response
		else:
			raise ValueError('Unexpected request {}'.format(message))

	def dump(self):
		return self.log

class MITMServerMaliciousG():
	def __init__(self, server, g, p, mode):
		self.server = server
		self.g = g
		self.p = p
		self.mode = mode
		self.session = self.getSession()
		self.log = []

	def getSession(self):
		if self.mode == '1':
			return 1
		elif self.mode == 'p':
			return 0
		elif self.mode == 'p-1':
			return (1, self.p-1)
		else:
			raise ValueError('Unexpected injection mode {}'.format(self.mode))

	def inject(self, message):
		if self.mode == '1':
			message['g'] = 1
		elif self.mode == 'p':
			message['g'] = self.p
		elif self.mode == 'p-1':
			message['g'] = self.p - 1
		else:
			raise ValueError('Unexpected injection mode {}'.format(self.mode))
		return message

	def getResponse(self, request):
		message = json.loads(request)
		if 'p' in message and 'g' in message and 'A' in message:
			message = self.inject(message)
			response = self.server.getResponse(json.dumps(message))

			return response
		elif 'ciphertext' in request:
			message = base64.b64decode(json.loads(request)['ciphertext'])
			if self.mode == 'p-1':
				shared_key = sha1(self.getSession()[0].to_bytes(192, 'little'))[:16]
				try:
					plaintext = util.flattenAndUnpad(ciphers.decryptCBC(message,
									lambda block: decryptAES(shared_key, block, 128)))
				except ValueError as e:
					shared_key = sha1(self.getSession()[1].to_bytes(192, 'little'))[:16]
					plaintext = util.flattenAndUnpad(ciphers.decryptCBC(message,
									lambda block: decryptAES(shared_key, block, 128)))
			else:
				shared_key = sha1(self.getSession().to_bytes(192, 'little'))[:16]
				plaintext = util.flattenAndUnpad(ciphers.decryptCBC(message,
								lambda block: decryptAES(shared_key, block, 128)))

			self.log.append(('Client -> Server', plaintext))

			response = self.server.getResponse(request)

			return response
		else:
			raise ValueError('Unexpected request {}'.format(message))

	def dump(self):
		return self.log

def challenge34Echo(client_message):
	server = EchoServer()
	client = Client(server)
	client.handshake()
	server_response = client.send(client_message)
	return server_response

def challenge34MITM(client_message):
	server = EchoServer()
	mitm_server = MITMServer(server)
	client = Client(mitm_server)

	client.handshake()
	client.send(client_message)

	intercepted = mitm_server.dump()
	return intercepted

def challenge35(client_message, g, p, mode):
	print('Challenge 35: g={}'.format(mode))
#	print('p=',p)
	server = EchoServer()
	mitm_server = MITMServerMaliciousG(server, g, p, mode)
	client = Client(mitm_server)

	client.handshake()
	try:
		client.send(client_message)
	except ValueError as e:
		print(e)

	intercepted = mitm_server.dump()
	return intercepted[0]

def challenge36(N, g, k, email, password):
	"""Secure Remote Password (SRP) authentication handshake"""
	print('Challenge 36')
	server = srp.Server(N, g, k)
	server.addUser(email, password)
	client = srp.Client(server, N, g, k)
	return client.authenticate(email, password)

def challenge37(N, g, k, email, password, A):
	"""Authenticate using malicious client public key and no password"""
	print('Challenge 37: A={}/N'.format(A/N))
	server = srp.Server(N, g, k)
	server.addUser(email, password)
	client = srp.MaliciousClient(server)
	return client.authenticate(email, A)

def challenge38(password_list):
	"""Offline dictionary attack on simplified SRP
	PAKE algorithms are meant to prevent MITM attackers from offline brute force
	password guessing
	"""
	print('Challenge 38')
	N = dh.RFC3526_1536_p
	g = dh.RFC3526_1536_g
	k = 3

	server = srp.MITM(N, g, k, password_list)
	client = srp.Client(server, N, g, k)
	password = secrets.choice(password_list)
	client.authenticate('user@example.com', password)

	return ('user@example.com', password) in server.credentials
