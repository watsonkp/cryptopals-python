#include "stdio.h"
#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/aes.h"

// nm -D libcrypto.so | grep EVP | less
// nm -D libcrypto.so | grep -i hmac | less

void handleErrors(char* message) {
	printf("%s", message);
}

void printHex(const unsigned char* bytes, unsigned int len) {
	for (int i = 0; i<len; i++) {
		printf("%02x", bytes[i]);
	}
	printf("\n");
}

void sha1(const unsigned char* message, size_t message_len, unsigned char** digest, unsigned int *digest_len) {
	EVP_MD_CTX *mdctx;
	if ((mdctx = EVP_MD_CTX_new()) == NULL) {
		handleErrors("Error: EVP_MD_CTX_new()\n");
	}

	if (1 != EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL)) {
		handleErrors("Error: EVP_DigestInit_ex()\n");
	}

	if (1 != EVP_DigestUpdate(mdctx, message, message_len)) {
		handleErrors("Error: EVP_DigestInit_ex()\n");
	}

	if ((*digest = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_sha1()))) == NULL) {
		handleErrors("Error: OPENSSL_malloc()\n");
	}

	if (1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len)) {
		handleErrors("Error: EVP_DigestFinal_ex()\n");
	}

	EVP_MD_CTX_free(mdctx);
}

void sha256(const unsigned char* message, size_t message_len, unsigned char** digest, unsigned int *digest_len) {
	EVP_MD_CTX *mdctx;
	if ((mdctx = EVP_MD_CTX_new()) == NULL) {
		handleErrors("Error: EVP_MD_CTX_new()\n");
	}

	if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
		handleErrors("Error: EVP_DigestInit_ex()\n");
	}

	if (1 != EVP_DigestUpdate(mdctx, message, message_len)) {
		handleErrors("Error: EVP_DigestInit_ex()\n");
	}

	if ((*digest = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL) {
		handleErrors("Error: OPENSSL_malloc()\n");
	}

	if (1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len)) {
		handleErrors("Error: EVP_DigestFinal_ex()\n");
	}

	EVP_MD_CTX_free(mdctx);
}

unsigned char* encryptAES(const unsigned char* userKey, const int bits, const unsigned char* plaintext) {
	unsigned char* ciphertext = malloc(16 * (sizeof(char)));
	AES_KEY *key = malloc(sizeof (*key));

	int ret;
	if ((ret = AES_set_encrypt_key(userKey, bits, key)) != 0) {
		printf("ERROR: aes_set_encrypt_key()==%d\n", ret);
	}
	AES_encrypt(plaintext, ciphertext, key);

	free(key);

	return ciphertext;
}

unsigned char* decryptAES(const unsigned char* userKey, const int bits, const unsigned char* ciphertext) {
	unsigned char* plaintext = malloc(16 * (sizeof(char)));
	AES_KEY *key = malloc(sizeof (*key));

	int ret;
	if ((ret = AES_set_decrypt_key(userKey, bits, key)) != 0) {
		printf("ERROR: aes_set_encrypt_key()==%d\n", ret);
	}
	AES_decrypt(ciphertext, plaintext, key);

	free(key);

	return plaintext;
}

//int main(int argc, char** argv) {
//	printf("Hello, world!\n");
//
//	const unsigned char* message = "AAAABBBBCCCCDDDD";
//	size_t message_len = 16;
//	unsigned char** digest = malloc(sizeof *digest);
//	unsigned int *digest_len = malloc(sizeof *digest_len);
//
//	sha256(message, message_len, digest, digest_len);
//
//	printf("%d\n", *digest_len);
//	for (int i = 0; i < *digest_len; i++) {
//		printf("%x", (*digest)[i]);
//	}
//	printf("\n");
//
//	free(digest);
//	free(digest_len);

//	const unsigned char* plaintext = "AAAABBBBCCCCDDDD";
//	printHex(plaintext, 16);
//	const unsigned char* userKey = "YELLOW SUBMARINE";
//	printHex(userKey, 16);
//	unsigned char* ciphertext = encryptAES(userKey, 128, plaintext);
//	printHex(ciphertext, 16);
//	unsigned char* decrypted = decryptAES(userKey, 128, ciphertext);
//	printHex(decrypted, 16);
//
//	return 0;
//}
