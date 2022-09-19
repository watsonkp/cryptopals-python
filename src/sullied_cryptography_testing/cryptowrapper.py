from ctypes import *

CRYPTO_WRAPPER = cdll.LoadLibrary('libcryptowrapper-0.1.0.so')

class CryptoException(Exception):
	"""
	Represents libcrypto errors.
	"""
	pass

def generatePrime(bits):
	"""
	Attempts to generate a random prime number with the specified bit length and top two bits set.

	:param bits: The length of the prime number to be generated.
	:type bits: int
	:raises CryptoException: Represents libcrypto errors that occurred during generation.
	:return: The generated prime number.
	:rtype: int
	"""
	hex_buffer = c_char_p(None)
	hex_buffer_length = c_int(0)
	error_buffer = c_char_p(None)
	error_buffer_length = c_int(0)
	status = CRYPTO_WRAPPER.generatePrime(bits, byref(hex_buffer), byref(hex_buffer_length), byref(error_buffer), byref(error_buffer_length))

	# Handle libcrypto errors.
	if status != 0:
		error_message = string_at(error_buffer, error_buffer_length).decode('utf-8')
		raise CryptoException(error_message)

	# Decode hexadecimal string representation and return integer
	hex_encoded_prime = string_at(hex_buffer, hex_buffer_length).decode('utf-8')
	return int(hex_encoded_prime, 16)

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
