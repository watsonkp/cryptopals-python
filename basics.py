import base64
import cryptowrapper
import ciphers

def challenge7():
	with open('./data/7.txt') as f:
		data = base64.b64decode(f.read())
	return ciphers.decryptECB(data, lambda block: cryptowrapper.decryptAES("YELLOW SUBMARINE".encode('utf-8'), block, 128))
