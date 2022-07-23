from ctypes import *

CRYPTO_WRAPPER = cdll.LoadLibrary("./libcryptowrapper.so")

def sha1(message):
	digest = c_char_p(None)
	digest_len = c_int(0)

	CRYPTO_WRAPPER.sha1(c_char_p(message), len(message), byref(digest), byref(digest_len))

	return string_at(digest, digest_len)

def sha256(message):
	digest = c_char_p(None)
	digest_len = c_int(0)

	CRYPTO_WRAPPER.sha256(c_char_p(message), len(message), byref(digest), byref(digest_len))

	return string_at(digest, digest_len)

# TODO: implement binding
def hmac(message, salt):
	#CRYPTO_WRAPPER.hmac(c_char_p("sha256"), message, salt)
	return sha256(message)

def encryptAES(key, message, bits):
	ciphertext = CRYPTO_WRAPPER.encryptAES(c_char_p(key), bits, c_char_p(message[:16]))
	return string_at(ciphertext, 16)

def decryptAES(key, message, bits):
	plaintext = CRYPTO_WRAPPER.decryptAES(c_char_p(key), bits, c_char_p(message[:16]))
	return string_at(plaintext, 16)
