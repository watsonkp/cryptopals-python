import base64
from sullied_cryptography_testing import cryptowrapper
from sullied_cryptography_testing import ciphers

def challenge7():
	with open('./tests/data/7.txt') as f:
		data = base64.b64decode(f.read())
	return ciphers.decryptECB(data, lambda block: cryptowrapper.decryptAES("YELLOW SUBMARINE".encode('utf-8'), block, 128))
