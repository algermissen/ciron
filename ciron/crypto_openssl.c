/*
 * This file implements the functions declared in crypto.h using libcrypto
 * of the OpenSSL library.
 */
#include <string.h>
#include <limits.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#include "ciron.h"
#include "common.h"

CironError ciron_encrypt(CironContext context, CironAlgorithm algorithm,
		const unsigned char *key, const unsigned char *iv,
		const unsigned char *data, size_t data_len, unsigned char *buf, size_t *sizep) {
	int r;
	int n;
	int n2;
	EVP_CIPHER_CTX ctx;
#if 0
	ciron_trace_bytes("KEY", key, 32);
	ciron_trace_bytes("IV", iv, 16);
#endif

	EVP_CIPHER_CTX_init(&ctx);

	if (strcmp(algorithm->name, CIRON_AES_128_CBC->name) == 0) {
		if ((r = EVP_EncryptInit(&ctx, EVP_aes_128_cbc(), key, iv)) != 1) {
			/* FIXME https://github.com/algermissen/ciron/issues/12 . And see three more occurrances below */
			return ciron_set_error(context, __FILE__, __LINE__, ERR_get_error(),
					CIRON_CRYPTO_ERROR, "Unable to initialize encrypt cipher");
		}
	} else if (strcmp(algorithm->name, CIRON_AES_256_CBC->name) == 0) {
		if ((r = EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), key, iv)) != 1) {
			/* See https://github.com/algermissen/ciron/issues/12 */
			return ciron_set_error(context, __FILE__, __LINE__, ERR_get_error(),
					CIRON_CRYPTO_ERROR, "Unable to initialize encrypt cipher");
		}
	} else {
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
				CIRON_ERROR_UNKNOWN_ALGORITHM,
				"Algorithm %s not recognized for encryption", algorithm->name);
	}
	if ((r = EVP_EncryptUpdate(&ctx, buf, &n, data, data_len)) != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		return ciron_set_error(context, __FILE__, __LINE__, ERR_get_error(),
				CIRON_CRYPTO_ERROR, "Unable to encrypt");
	}

	if ((r = EVP_EncryptFinal(&ctx, buf + n, &n2)) != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		return ciron_set_error(context, __FILE__, __LINE__, ERR_get_error(),
				CIRON_CRYPTO_ERROR, "Unable to encrypt");
	}
	EVP_CIPHER_CTX_cleanup(&ctx);

	*sizep = n + n2;
	return CIRON_OK;
}

CironError ciron_decrypt(CironContext context, CironAlgorithm algorithm,
		const unsigned char *key, const unsigned char *iv,
		const unsigned char *data, size_t data_len, unsigned char *buf, size_t *sizep) {
	int r;
	int n;
	int n2;
	EVP_CIPHER_CTX ctx;
#if 0
	ciron_trace_bytes("KEY", key, 32);
	ciron_trace_bytes("IV", iv, 16);
	ciron_trace_bytes("DATA", data, data_len);
#endif

	EVP_CIPHER_CTX_init(&ctx);

	if (strcmp(algorithm->name, CIRON_AES_128_CBC->name) == 0) {
		if ((r = EVP_DecryptInit(&ctx, EVP_aes_128_cbc(), key, iv)) != 1) {
			/* See https://github.com/algermissen/ciron/issues/12 */
			return ciron_set_error(context, __FILE__, __LINE__, ERR_get_error(),
					CIRON_CRYPTO_ERROR, "Unable to initialize decrypt cipher");
		}
	} else if (strcmp(algorithm->name, CIRON_AES_256_CBC->name) == 0) {
		if ((r = EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), key, iv)) != 1) {
			/* See https://github.com/algermissen/ciron/issues/12 */
			return ciron_set_error(context, __FILE__, __LINE__, ERR_get_error(),
					CIRON_CRYPTO_ERROR, "Unable to initialize decrypt cipher");
		}
	} else {
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
				CIRON_ERROR_UNKNOWN_ALGORITHM,
				"Algorithm %s not recognized for decryption", algorithm->name);
	}
	if ((r = EVP_DecryptUpdate(&ctx, buf, &n, data, data_len)) != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		return ciron_set_error(context, __FILE__, __LINE__, ERR_get_error(),
				CIRON_CRYPTO_ERROR, "Unable to decrypt");
	}

	if ((r = EVP_DecryptFinal(&ctx, buf + n, &n2)) != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		return ciron_set_error(context, __FILE__, __LINE__, ERR_get_error(),
				CIRON_CRYPTO_ERROR, "Unable to decrypt");
	}
	EVP_CIPHER_CTX_cleanup(&ctx);
	*sizep = n + n2;

	return CIRON_OK;
}

CironError ciron_generate_key(CironContext context,
		const unsigned char* password, size_t password_len,
		const unsigned char *salt, size_t salt_len, CironAlgorithm algorithm,
		size_t iterations, unsigned char *buf) {
	int keylen;
	int r;

	keylen = NBYTES(algorithm->key_bits);
	assert(keylen <= MAX_KEY_BYTES);

	/*
	 * http://www.manualpages.de/FreeBSD/FreeBSD-ports-9.0-RELEASE/man3/PKCS5_PBKDF2_HMAC_SHA1.3.html
	 * http://www.opensource.apple.com/source/OpenSSL/OpenSSL-22/openssl/crypto/evp/p5_crpt2.c
	 *
	 */
	if ((r = PKCS5_PBKDF2_HMAC_SHA1((const void*) password, password_len, salt,
			salt_len, iterations, keylen, buf)) != 1) {
		return ciron_set_error(context, __FILE__, __LINE__, ERR_get_error(),
				CIRON_CRYPTO_ERROR, "Unable to generate key for algorithm %s",
				algorithm->name);
	}

	return CIRON_OK;
}

CironError ciron_generate_salt(CironContext context, size_t nbytes,
		unsigned char *buf) {
	int r;
	unsigned char salt_bytes[MAX_SALT_BYTES];
	assert(nbytes <= MAX_SALT_BYTES);

	if ((r = RAND_bytes(salt_bytes, nbytes)) != 1) {
		return ciron_set_error(context, __FILE__, __LINE__, ERR_get_error(),
				CIRON_CRYPTO_ERROR, "Unable to get %d random bytes", nbytes);
	}
	ciron_bytes_to_hex(salt_bytes, nbytes, buf);

	return CIRON_OK;
}

CironError ciron_generate_iv(CironContext context, size_t nbytes,
		unsigned char *buf) {
	int r;
	if ((r = RAND_bytes(buf, nbytes)) != 1) {
		return ciron_set_error(context, __FILE__, __LINE__, ERR_get_error(),
				CIRON_CRYPTO_ERROR, "Unable to get %d random bytes", nbytes);
	}

	return CIRON_OK;
}

CironError ciron_hmac(CironContext context, CironAlgorithm algorithm,
		const unsigned char *password, size_t password_len,
		const unsigned char *salt_bytes, size_t salt_len, size_t iterations,
		const unsigned char *data, size_t data_len, unsigned char *result,
		size_t *result_len) {
	CironError e;
	unsigned char buffer_key_bytes[MAX_KEY_BYTES];
	size_t key_len;
	unsigned int rlen;


	key_len = NBYTES(algorithm->key_bits);
	assert(key_len <= MAX_KEY_BYTES);

	if ((e = ciron_generate_key(context, password, password_len, salt_bytes,
			salt_len, algorithm, iterations, buffer_key_bytes)) != CIRON_OK) {
		return e;
	}

	if (strcmp(algorithm->name, CIRON_SHA_256->name) == 0) {
		if ((HMAC(EVP_sha256(), buffer_key_bytes, key_len, data, data_len,
				result, &rlen)) == NULL ) {
			return ciron_set_error(context, __FILE__, __LINE__, ERR_get_error(),
					CIRON_CRYPTO_ERROR, "Unable to calculate HMAC");
		}
	} else {
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
				CIRON_ERROR_UNKNOWN_ALGORITHM,
				"Algorithm %s not recognized for HMAC calculation",
				algorithm->name);
	}
	assert(rlen > 0 && rlen < UINT_MAX);
	*result_len = (size_t)rlen;
	return CIRON_OK;
}

