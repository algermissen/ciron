#ifndef CRYPTO_H
#define CRYPTO_H 1
#include "ciron.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Generate a random salt and store in buffer hex-encoded.
 *
 * This function generates a salt of the required length of nbytes and
 * stores it in the provided buffer.
 *
 * The hex-encoding causes the result to be exactly 2xnbytes long. The
 * provided buffer must have at least that size.
 *
 * The result will not be \0 terminated.
 */
CironError CIRONAPI ciron_generate_salt(CironContext context, int nbytes,
		unsigned char *buf);


/** Generate a random initialization vector and store in buffer.
 *
 * This function generates an initialization vector of the required length of nbytes and
 * stores it in the provided buffer.
 *
 * The provided buffer must have at least the size of nbytes.
 *
 * The result will not be \0 terminated.
 */
CironError CIRONAPI ciron_generate_iv(CironContext context, int nbytes,
		unsigned char *buf);


/** Generate a key using the provided password, salt, and
 * iterations.
 *
 * This function generates a cryptographic key using the provided
 * password, salt, and iterations and stores the key in the
 * provided buffer.
 *
 * The buffer must have at least the keysize that corresponds to the
 * algorithm. For convenience ciron defines MAX_KEYSIZE which
 * reflects the largest key size of all algorithms provided by
 * ciron. You can safely define a buffer of that size and use it
 * with any of the algorithms.
 *
 * The result will not be \0 terminated.
 */
CironError CIRONAPI ciron_generate_key(CironContext context,
		const unsigned char* password, int password_len,
		const unsigned char *salt, int salt_len, Algorithm algorithm,
		int iterations, unsigned char *buf);

/** Encrypt the provided data using the specified algorithm.
 *
 * This function encrypts the provided data and stores the
 * result in buffer. The cryptographic key and an initialization
 * vector of a suitable size must also be given.
 *
 * The buffer must be large enough to hold the encrypted
 * result. Since the actual length depends on the input
 * data size and provided parameters the responsibility
 * to allocate the buffer is on the caller.
 *
 * At the moment, ciron uses only block ciphers and the
 * length of the encryption result can be calculated like
 * this:
 *
 * result_size = data_len + block_size - (data_len MOD clock_size)
 *
 * Meaning that the result will be at most one block size longer
 * that the provided data. In ciron.h declares a function
 * calculate_encryption_buffer_length() that can be used to obtain
 * that size from a given input length.
 *
 * The result will not be \0 terminated.
 *
 */
CironError CIRONAPI ciron_encrypt(CironContext context, Algorithm algorithm,
		const unsigned char *key, const unsigned char *iv,
		const unsigned char *data, int data_len, unsigned char *buf, int *sizep);

/** Decrypt the provided data using the specified algorithm.
 *
 * This function decrypts the provided data and stores the
 * result in buffer. The cryptographic key and an initialization
 * vector of a suitable size must also be given.
 *
 * The buffer must be large enough to hold the decrypted
 * result. Since the actual length depends on the input
 * data size and provided parameters the responsibility
 * to allocate the buffer is on the caller.
 *
 * At the moment, ciron uses only block ciphers and the
 * length of the decryption result can be calculated based
 * on the length of the encrypted data and the block size.
 *
 * Given that as of Mai 2013 I did not find a way to
 * solve the encryption size equation the other way round
 * I choose to simply use the encryption size, which will
 * be a bit too large, but definitely larger than the
 * decrypted result. The overhead is in my opinion not
 * significant as it is onlt a few bytes.
 *
 * The result will not be \0 terminated.
 *
 */
CironError CIRONAPI ciron_decrypt(CironContext context, Algorithm algorithm,
		const unsigned char *key, const unsigned char *iv,
		const unsigned char *data, int data_len, unsigned char *buf, int *sizep);


/** Calculates an HMAC from the provided data using password, salt,
 * algorithm, and iterations.
 *
 * This function calculates an HMAC value of the provided data. First, the salt
 * will be used to derive a cryptographic key from the password to create a key
 * of the required length for algorithm.
 *
 * Then, the generated key will be used to create the HMAC value using the supplied
 * algorithm.
 *
 * The HMAC value will be stored in the provided buffer, which must be big enough
 * to hold HMAC values generated by the algorithm. For convenience, ciron
 * defines MAX_HMAC_BYTES to hold the largest possible HMAC size given the currently
 * provided algorithms.
 *
 * The result will not be \0 terminated.
 *
 */
CironError CIRONAPI ciron_hmac(CironContext context, Algorithm algorithm,
		const unsigned char *password, int password_len,
		const unsigned char *salt_bytes, int salt_len, int iterations,
		const unsigned char *data, int data_len, unsigned char *result,
		int *result_len);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* !defined CRYPTO_H */
