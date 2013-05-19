#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "ciron.h"
#include "common.h"
#include "crypto.h"
#include "base64url.h"

#define DELIM '*'
#define MAC_FORMAT_VERSION "1"
#define MAC_PREFIX "Fe26." MAC_FORMAT_VERSION

/*
 * These are local helper structs to bind the various char pointers
 * and their lengths together. For const and non-const.
 */
struct const_chars_and_len {
	const unsigned char *chars;
	int len;
};

struct chars_and_len {
	unsigned char *chars;
	int len;
};

/*
 * Parses an unsigned char array until the next delimiter is found. Sets the
 * supplied bytes_and_len structure to point to the start of the parsed sequence
 * and its len field to contain the length of the parsed sequence.
 *
 * This function can not be used to parse a chunk of unisgned chars that do not
 * contain a delimiter. The rationale for this design is that the last sequence
 * in a parsed token needs not be parsed because the end is known already.
 *
 * Returns an error if the end of the supplied data is reached bevore a delimiter is
 * found.
 */
static CironError parse(CironContext context, const unsigned char *data,
		int len, struct const_chars_and_len *balp);

/* Variants of parse. Not sure whether that is truely needed, but I want to limit possible attack vectors */
static CironError parse_fixed_len(CironContext context,
		const unsigned char *data, int len, int expected_len,
		struct const_chars_and_len *balp);
static CironError parse_max_len(CironContext context, const unsigned char *data,
		int len, int max_len, struct const_chars_and_len *balp);

int calculate_encryption_buffer_length(Options encryption_options, int data_len) {
	/* for all CBC. But see https://github.com/algermissen/ciron/issues/5 */
	int cipher_block_size = 16;
	/* Taken from http://www.obviex.com/articles/ciphertextsize.aspx */
	return data_len + cipher_block_size - (data_len % cipher_block_size);
}

/*
 * The layouts of the two functions below aims to show explicitly what is
 * being calculated. This isn't called often, so it is ok to not optimize
 * the calculations.
 */

int calculate_seal_buffer_length(Options encryption_options,
		Options integrity_options, int data_len) {

	int len = 6; /* MAC_PREFIIX */
	len++; /* delimiter */
	len += 0; /* password id impl. pending */
	len++; /* delimiter */
	len = len + (NBYTES(encryption_options->salt_bits) * 2); /* enc salt (encr.options.salt_bits/8) * 2 (wegen hex) */
	len++; /* delimiter */
	/* FIXME try macro for calc below */
	len += ceil(
			(double) (NBYTES(encryption_options->algorithm->iv_bits) * 4) / 3); /* iv (encr.options.iv_bits/8) und dann den base64  platz dafuer */
	len++; /* delimiter */
	/* FIXME try macro for calc below */
	len += ceil(
			(double) (calculate_encryption_buffer_length(encryption_options,
					data_len) * 4) / 3); /* base64 of encrypted */
	len++; /* delimiter */
	len += NBYTES(integrity_options->salt_bits) * 2; /* integr. salt (integr.options.salt_bits/8) * 2 (wegen hex) */
	len++; /* delimiter */
	len += BASE64URL_ENCODE_SIZE(32); /* sha256 hmac result size as base 64*/
	return len;
}

int calculate_unseal_buffer_length(Options encryption_options,
		Options integrity_options, int data_len) {

	int len = data_len;

	len -= 6; /* MAC_PREFIIX */
	len--; /* delimiter */
	len -= 0; /* password id impl. pending */
	len--; /* delimiter */
	len = len - (NBYTES(encryption_options->salt_bits) * 2); /* enc salt (encr.options.salt_bits/8) * 2 (wegen hex) */
	len--; /* delimiter */
	len =
			len
					- ceil(
							(double) (NBYTES(encryption_options->algorithm->iv_bits)
									* 4) / 3); /* iv (encr.options.iv_bits/8) und dann den base64  platz dafuer */
	len--; /* delimiter */
	/* skipping, because we need the remains of len below.
	 len += ceil((double)(calculate_encryption_buffer_length(encryption_options,data_len) *4) / 3); * base64 of encrypted *
	 */
	len--; /* delimiter */
	len = len - (NBYTES(integrity_options->salt_bits) * 2); /* integr. salt (integr.options.salt_bits/8) * 2 (wegen hex) */
	len--; /* delimiter */
	len = len - ceil((double) (32 * 4) / 3); /* sha256 hmac result size as base 64*/

	/*
	 * Now len is the length of the base64-encoded encrypted
	 */

	len = floor((double) (len * 3) / 4);


	/*
	 * The result x would be calced by solving
	 *   len = x+blocksize - (x%blocksize)
	 * to x.
	 *
	 * No idea how to resolve the modulo term, hence I just return the encryption length since that is >= the original data length.
	 *
	 */
	/* FIXME: make these functions return CironError */
	if (len < 0) {
		len = 0;
	}
	return len;
}

CironError ciron_seal(CironContext context, const unsigned char *data,
		int data_len, const unsigned char* password, int password_len,
		Options encryption_options, Options integrity_options,
		unsigned char *buffer_encrypted_bytes, unsigned char *result, int *plen) {

	CironError e;
	/*
	 *  These are local buffers to hold data that is pointed to by the xxx_and_len structs
	 */
	unsigned char buffer_key_bytes[MAX_KEY_BYTES];
	unsigned char buffer_iv_bytes[MAX_IV_BYTES];
	unsigned char buffer_hmac_bytes[MAX_HMAC_BYTES];

	/*
	 * Variables to keep together pointer and length information
	 * of encryption data.
	 */
	struct chars_and_len encryption_salt_hex;
	struct chars_and_len key_bytes;
	struct chars_and_len iv_bytes;
	struct chars_and_len iv_base64url;
	struct chars_and_len encrypted_bytes;
	struct chars_and_len encrypted_base64url;

	/*
	 * Variables to keep together pointer and length information
	 * of integrity data.
	 */
	struct chars_and_len integrity_salt_hex;
	struct chars_and_len hmac_bytes;
	struct chars_and_len hmac_base64url;
	struct chars_and_len hmac_base_chars;

	/*
	 * This maintains position while filling the result buffer.
	 */
	unsigned char *result_ptr;

	/*
	 * Calculate number of salt bytes from provided options and
	 * verify that size is within limits.
	 */
	assert(NBYTES(encryption_options->salt_bits) <= MAX_SALT_BYTES);
	assert(NBYTES(integrity_options->salt_bits) <= MAX_SALT_BYTES);
	assert(NBYTES(encryption_options->algorithm->iv_bits) <= MAX_IV_BYTES);
	assert(NBYTES(encryption_options->algorithm->key_bits) <= MAX_KEY_BYTES);

	/*
	 * prefix*pwd*encSalt*iv64*data64* integritySalt*integrityHmac
	 * Write the prefix (and later on password id) to the result buffer.
	 * FIXME: password rotation pending
	 * FIXME: use memcpy
	 */

	/*
	 * Write the prefix, delimiter, empty password_id (implementation pending)
	 * and another delimiter. Advance the result pointer.
	 */
	assert(strlen(MAC_PREFIX) == 6);
	memcpy(result, (unsigned char*) MAC_PREFIX "**", 8);
	result_ptr = result + 8;

	/*
	 * Encryption salt generation. Because the encryption salt hex will
	 * be part of the result, we do not need a buffer but can store the
	 * hex-salt directly in the result.
	 * Note that the result is twice as long as the requested number of
	 * bytes.
	 */
	encryption_salt_hex.chars = result_ptr;
	encryption_salt_hex.len = NBYTES(encryption_options->salt_bits) * 2; /* Due to byte-to-hex conversion */
	if ((e = ciron_generate_salt(context, NBYTES(encryption_options->salt_bits),
			encryption_salt_hex.chars)) != CIRON_OK) {
		return e;
	}
	result_ptr += encryption_salt_hex.len;

	/*
	 * Add a '*' delimiter.
	 */
	*result_ptr = DELIM;
	result_ptr++;
#if 0
	*result_ptr = '\0';
	TRACE("STRING added salt |%s|\n" _ result);
#endif

	/*
	 * Encryption key handling. Because the key is not part of the
	 * result, we need to store the generated key in a buffer.
	 */

	key_bytes.len = NBYTES(encryption_options->algorithm->key_bits);
	key_bytes.chars = buffer_key_bytes;
	if ((e = ciron_generate_key(context, password, password_len,
			encryption_salt_hex.chars, encryption_salt_hex.len,
			encryption_options->algorithm, encryption_options->iterations,
			key_bytes.chars)) != CIRON_OK) {
		return e;
	}

	/*
	 * IV Handling. Because the IV bytes are not stored in the
	 * result (the base64 encoded IV is) we need to store the
	 * bytes in a buffer.
	 */

	iv_bytes.len = NBYTES(encryption_options->algorithm->iv_bits);
	iv_bytes.chars = buffer_iv_bytes;
	if ((e = ciron_generate_iv(context, iv_bytes.len, iv_bytes.chars))
			!= CIRON_OK) {
		return e;
	}

	/*
	 * Turn iv bytes into base64url encoded value. Because this value is part
	 * of the result, we can directly store it in the result and need no
	 * extra buffer here.
	 */
	iv_base64url.chars = result_ptr;
	ciron_base64url_encode(iv_bytes.chars, iv_bytes.len, iv_base64url.chars,
			&(iv_base64url.len));
	result_ptr += iv_base64url.len;

	/*
	 * Add a delimiter.
	 */
	*result_ptr = DELIM;
	result_ptr++;
#if 0
	*result_ptr = '\0';
	TRACE("STRING: added iv |%s|\n" _ result);
#endif

	/*
	 * Encrypt the data. Because the encrypted data is not part of the
	 * result (the base64url version is), we need a buffer to hold the encrypted
	 * binary data.
	 */
	encrypted_bytes.chars = buffer_encrypted_bytes;
	if ((e = ciron_encrypt(context, encryption_options->algorithm,
			key_bytes.chars, iv_bytes.chars, data, data_len,
			encrypted_bytes.chars, &(encrypted_bytes.len))) != CIRON_OK) {
		return e;
	}
#if 0
	TRACE("encrypted to %d bytes\n" _ encrypted_bytes.len);
	ciron_trace_bytes("encbytes", encrypted_bytes.chars, encrypted_bytes.len);
#endif

	/*
	 * Create base64url encoding of encypted binary data. Because the
	 * base64 version is part of the result string, we do not need a
	 * separate buffer but encode the data to the result directly.
	 */
	encrypted_base64url.chars = result_ptr;
	ciron_base64url_encode(encrypted_bytes.chars, encrypted_bytes.len,
			encrypted_base64url.chars, &(encrypted_base64url.len));
	result_ptr += encrypted_base64url.len;

	/*
	 * With the base64 encoding of the encrypted data the HMAC base sting
	 * ends and we note its length now.
	 */
	hmac_base_chars.chars = result;
	hmac_base_chars.len = result_ptr - result;

#if 0
	*result_ptr = '\0';
	TRACE("HMAC base string |%s|\n" _ result);
#endif
	/*
	 * Now that the HMAC base string end has been noted, we can add a delimiter.
	 */
	*result_ptr = DELIM;
	result_ptr++;
#if 0
	*result_ptr = '\0';
	TRACE("STRING: added encrypted |%s|\n" _ result);
#endif

	/* ----- Encryption portion done, now handle integrity ----- */

	/*
	 * Integrity salt generation. Because the salt is part of the result,
	 * we can generate the hex directly into the result without the need for
	 * a buffer.
	 *
	 * Note that the result is twice as long as the requested number of
	 * bytes.
	 */

	integrity_salt_hex.chars = result_ptr;
	integrity_salt_hex.len = NBYTES(integrity_options->salt_bits) * 2; /* Due to byte-to-hex conversion */
	if ((e = ciron_generate_salt(context, NBYTES(integrity_options->salt_bits),
			integrity_salt_hex.chars)) != CIRON_OK) {
		return e;
	}
	result_ptr += integrity_salt_hex.len;

	/*
	 * Add another delimiter.
	 */
	*result_ptr = DELIM;
	result_ptr++;
#if 0
	*result_ptr = '\0';
	TRACE("STRING: added integrity salt |%s|\n" _ result);
	TRACE("AAA-2.a hmac base_chars len: %d\n" _ hmac_base_chars.len);
#endif

	/*
	 * Now calculate the HMAC. Because the HMAC is not part of the result
	 * (the base64url version is), we need a buffer to hold the binary.
	 */
	hmac_bytes.chars = buffer_hmac_bytes;
	if ((e = ciron_hmac(context, integrity_options->algorithm, password,
			password_len, integrity_salt_hex.chars, integrity_salt_hex.len,
			integrity_options->iterations, hmac_base_chars.chars,
			hmac_base_chars.len, hmac_bytes.chars, &(hmac_bytes.len)))
			!= CIRON_OK) {
		return e;
	}
#if 0
	TRACE("AAA-2.b Hmac bytes len:%d\n" _ hmac_bytes.len);
#endif

	/*
	 * Generate the base64url encoded version of the HMAC. Because this is stored in
	 * the result directly, we need no buffer here, but encode directly to
	 * the result.
	 */
	hmac_base64url.chars = result_ptr;
	ciron_base64url_encode(hmac_bytes.chars, hmac_bytes.len,
			hmac_base64url.chars, &(hmac_base64url.len));
	result_ptr += hmac_base64url.len;

	/*
	 * Calculate the length of the result.
	 *
	 * Note that we do not \0 terminate it.
	 */
	*plen = result_ptr - result;

	return CIRON_OK;
}

CironError ciron_unseal(CironContext context, const unsigned char *data,
		int data_len, const unsigned char* password, int password_len,
		Options encryption_options, Options integrity_options,
		unsigned char *buffer_encrypted_bytes, unsigned char *result, int *plen) {

	CironError e;

	/*
	 * These are parse from the incoming data and point into that data block.
	 * No copy is made.
	 */
	struct const_chars_and_len prefix;
	struct const_chars_and_len password_id;
	struct const_chars_and_len encryption_salt_hexchars;
	struct const_chars_and_len encryption_iv_b64urlchars;
	struct const_chars_and_len encrypted_data_b64urlchars;
	struct const_chars_and_len integrity_salt_hexchars;
	struct const_chars_and_len integrity_hmac_b64urlchars;
	struct const_chars_and_len hmac_base_chars;

	/*
	 *  These are local buffers to hold data that is pointed to by the xxx_and_len structs
	 */
	unsigned char buffer_encryption_key_bytes[MAX_KEY_BYTES];
	unsigned char buffer_encryption_iv_bytes[MAX_IV_BYTES];
	unsigned char buffer_integrity_hmac_bytes[MAX_HMAC_BYTES];
	unsigned char buffer_incoming_integrity_hmac_bytes[MAX_HMAC_BYTES];

	/*
	 * Variables to keep together pointer and length information
	 * of encryption data.
	 */

	struct chars_and_len encryption_key_bytes;
	struct chars_and_len encryption_iv_bytes;
	struct chars_and_len encrypted_bytes;
	struct chars_and_len decrypted_bytes;

	/*
	 * Variables to keep together pointer and length information
	 * of integrity data.
	 */
	struct chars_and_len integrity_hmac_bytes;
	struct chars_and_len incodming_integrity_hmac_bytes;

	/*
	 * These maintain parsing position when extracting fields from incoming data
	 */
	const unsigned char *data_ptr;
	int data_remain_len;

	/*
	 * Calculate number of salt bytes from provided options and
	 * verify that size is within limits.
	 */
	assert(NBYTES(encryption_options->salt_bits) <= MAX_SALT_BYTES);
	assert(NBYTES(integrity_options->salt_bits) <= MAX_SALT_BYTES);
	assert(NBYTES(encryption_options->algorithm->iv_bits) <= MAX_IV_BYTES);
	assert(NBYTES(encryption_options->algorithm->key_bits) <= MAX_KEY_BYTES);

	/*
	 * Remember the start of the base string for later HMAC generation for
	 * HMAC validation. We will set length later, once we are at that
	 * parsing position.
	 */
	hmac_base_chars.chars = data;

	/*
	 * Initialize vars that maintain parsing state.
	 */
	data_ptr = data;
	data_remain_len = data_len;

	/*
	 * Parse the prefix and validate.
	 */
	if ((e = parse_fixed_len(context, data_ptr, data_remain_len, 6, &prefix)
			!= CIRON_OK)) {
		return e;
	}
	if (memcmp(prefix.chars, MAC_PREFIX, 6) != 0) {
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
				CIRON_TOKEN_PARSE_ERROR, "Invalid prefix");
	}

	/* Skip prefix and delimiter */
	data_ptr += prefix.len + 1;
	data_remain_len -= prefix.len + 1;

	/*
	 * Parse password (implementation pending, so currently we expect it to be empty.
	 */

	if ((e = parse_fixed_len(context, data_ptr, data_remain_len, 0,
			&password_id) != CIRON_OK)) {
		return e;
	}
	/* Skip password and delimiter */
	data_ptr += password_id.len + 1;
	data_remain_len -= password_id.len + 1;

	/*
	 * Parse encryption salt.
	 */
	if ((e = parse_fixed_len(context, data_ptr, data_remain_len,
			NBYTES(encryption_options->salt_bits) * 2,
			&encryption_salt_hexchars) != CIRON_OK)) {
		return e;
	}

	/* Skip salt and delimiter */
	data_ptr += encryption_salt_hexchars.len + 1;
	data_remain_len -= encryption_salt_hexchars.len + 1;

	/*
	 * Parse encryption IV base64url sequence.
	 */
	if ((e = parse_max_len(context, data_ptr, data_remain_len, MAX_IV_B64CHARS,
			&encryption_iv_b64urlchars) != CIRON_OK)) {
		return e;
	}

	/* Skip IV base64url and delimiter */
	data_ptr += encryption_iv_b64urlchars.len + 1;
	data_remain_len -= encryption_iv_b64urlchars.len + 1;

	/*
	 * Parse encrypted base64url encoded sequence. There
	 * is no size checking here. it is the responsibility
	 * of the caller to supply the correct data_len value
	 * so that we do not read past the end of the sealed
	 * data.
	 */
	if ((e = parse(context, data_ptr, data_remain_len,
			&encrypted_data_b64urlchars) != CIRON_OK)) {
		return e;
	}
	/* skip encrypted and delimiter */
	data_ptr += encrypted_data_b64urlchars.len + 1;
	data_remain_len -= encrypted_data_b64urlchars.len + 1;

	/*
	 * Now we can set the HMAC base string length. We must
	 * substract one because we already advanced to the delimiter
	 * above. And the elimiter is not part of the base string.
	 */
	hmac_base_chars.len = data_ptr - data - 1;

	/*
	 * Now we parse the integrity salt.
	 */
	if ((e = parse_fixed_len(context, data_ptr, data_remain_len,
			NBYTES(integrity_options->salt_bits) * 2, &integrity_salt_hexchars)
			!= CIRON_OK)) {
		return e;
	}
	/* skip salt and delimiter */
	data_ptr += integrity_salt_hexchars.len + 1;
	data_remain_len -= (integrity_salt_hexchars.len + 1);

	/*
	 * Now we parse the base64url encoded HMAC value.
	 * We do not need to parse for delimiter here, because it
	 * is the last portion of the input anyhow.
	 */
	integrity_hmac_b64urlchars.chars = data_ptr;
	integrity_hmac_b64urlchars.len = data_remain_len - 1; /* FIXME: why? */
	if (integrity_hmac_b64urlchars.len > 43) { /* FIXME: why is macro not working? */
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
				CIRON_TOKEN_PARSE_ERROR,
				"Base64url encoded string of HMAC is too long. Parsed %d bytes, but max is %d",
				integrity_hmac_b64urlchars.len, 43);
	}

	/*
	 * Calculate integrity HMAC using the base string. This value is the
	 * used to validate the incoming HMAC in the input.
	 */
	integrity_hmac_bytes.chars = buffer_integrity_hmac_bytes;
	if ((e = ciron_hmac(context, integrity_options->algorithm, password,
			password_len, integrity_salt_hexchars.chars,
			integrity_salt_hexchars.len, integrity_options->iterations,
			hmac_base_chars.chars, hmac_base_chars.len,
			integrity_hmac_bytes.chars, &(integrity_hmac_bytes.len)))
			!= CIRON_OK) {
		return e;
	}

	/*
	 * Turn incoming base64url encoded HMAC value into binary for comparison.
	 */
	incodming_integrity_hmac_bytes.chars = buffer_incoming_integrity_hmac_bytes;
	ciron_base64url_decode(integrity_hmac_b64urlchars.chars,
			integrity_hmac_b64urlchars.len,
			incodming_integrity_hmac_bytes.chars,
			&(incodming_integrity_hmac_bytes.len));

	/*
	 * Lengths of the HMACs must match, of course.
	 */
	if (integrity_hmac_bytes.len != incodming_integrity_hmac_bytes.len) {
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
				CIRON_TOKEN_VALIDATION_ERROR,
				"HMAC signature invalid (lenght differ)");
	}

	/*
	 * And check for HMAC equality. If this succeeds, we know that no one has tampered
	 * with the * input.
	 */
	if (memcmp(incodming_integrity_hmac_bytes.chars, integrity_hmac_bytes.chars,
			integrity_hmac_bytes.len) != 0) {
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
				CIRON_TOKEN_VALIDATION_ERROR, "HMAC signature invalid");
	}

	/*
	 * Generate an encryption key using the given salt and algorithm.
	 */
	encryption_key_bytes.len = NBYTES(encryption_options->algorithm->key_bits);
	encryption_key_bytes.chars = buffer_encryption_key_bytes;
	if ((e = ciron_generate_key(context, password, password_len,
			encryption_salt_hexchars.chars, encryption_salt_hexchars.len,
			encryption_options->algorithm, encryption_options->iterations,
			encryption_key_bytes.chars)) != CIRON_OK) {
		return e;
	}

	/*
	 * Base64url decode the encryption IV. The size has been
	 * verified during parsing, but we could do it
	 * again here using the other macro. Try it -> FIXME
	 */
	encryption_iv_bytes.chars = buffer_encryption_iv_bytes;
	ciron_base64url_decode(encryption_iv_b64urlchars.chars,
			encryption_iv_b64urlchars.len, encryption_iv_bytes.chars,
			&(encryption_iv_bytes.len));

	/*
	 * Turn base64 of encrypted into bytes for decrypting. It is
	 * caller's responsibility that the buffer is large enough.
	 */
	encrypted_bytes.chars = buffer_encrypted_bytes;
	ciron_base64url_decode(encrypted_data_b64urlchars.chars,
			encrypted_data_b64urlchars.len, encrypted_bytes.chars,
			&(encrypted_bytes.len));

	/*
	 * Decrypt the data.
	 */
	decrypted_bytes.chars = result;
	if ((e = ciron_decrypt(context, encryption_options->algorithm,
			encryption_key_bytes.chars, encryption_iv_bytes.chars,
			encrypted_bytes.chars, encrypted_bytes.len, decrypted_bytes.chars,
			&(decrypted_bytes.len))) != CIRON_OK) {
		return e;
	}

	*plen = decrypted_bytes.len;

	return CIRON_OK;
}

static CironError parse(CironContext context, const unsigned char *data,
		int len, struct const_chars_and_len *balp) {
	int pos = 0;
	balp->chars = data;

	while (pos < len) {
		if (data[pos] == DELIM) {
			balp->len = pos;
			return CIRON_OK;
		}
		pos++;
	}

	return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
			CIRON_TOKEN_PARSE_ERROR,
			"End of char sequence reached before finding delimiter");
}
static CironError parse_fixed_len(CironContext context,
		const unsigned char *data, int len, int expected_len,
		struct const_chars_and_len *balp) {
	int pos = 0;
	balp->chars = data;
	if (expected_len > len) {
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
				CIRON_TOKEN_PARSE_ERROR,
				"Remaining length %d smaller than expected length %d", len,
				expected_len);
	}

	while (pos < len && pos <= expected_len) {
		if (data[pos] == DELIM) {
			if (pos != expected_len) {
				return ciron_set_error(context, __FILE__, __LINE__,
						NO_CRYPTO_ERROR, CIRON_TOKEN_PARSE_ERROR,
						"Expected parse length of %d, but only got %d",
						expected_len, pos);
			}
			balp->len = pos;
			return CIRON_OK;
		}
		pos++;
	}

	return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
			CIRON_TOKEN_PARSE_ERROR,
			"End of char sequence or expected length reached before finding delimiter");
}

static CironError parse_max_len(CironContext context, const unsigned char *data,
		int len, int max_len, struct const_chars_and_len *balp) {
	int pos = 0;
	balp->chars = data;
	if (max_len > len) {
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
				CIRON_TOKEN_PARSE_ERROR,
				"Remaining length %d smaller than expected max length %d", len,
				max_len);
	}

	while (pos < len && pos <= max_len) {
		if (data[pos] == DELIM) {
			balp->len = pos;
			return CIRON_OK;
		}
		pos++;
	}

	return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
			CIRON_TOKEN_PARSE_ERROR,
			"End of char sequence or expected length reached before finding delimiter");
}
