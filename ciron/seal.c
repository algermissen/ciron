#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
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
	size_t len;
};

struct chars_and_len {
	unsigned char *chars;
	size_t len;
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
		size_t len, struct const_chars_and_len *balp);

/* Variants of parse. Not sure whether that is truely needed, but I want to limit possible attack vectors */
static CironError parse_fixed_len(CironContext context,
		const unsigned char *data, size_t len, size_t expected_len,
		struct const_chars_and_len *balp);
static CironError parse_max_len(CironContext context, const unsigned char *data,
		size_t len, size_t max_len, struct const_chars_and_len *balp);



CironError ciron_calculate_encryption_buffer_length(CironContext context, size_t data_len, size_t *result_len) {
	/* for all CBC. But see https://github.com/algermissen/ciron/issues/5 */
	size_t cipher_block_size = CIPHER_BLOCK_SIZE;

	/* Below we calculate the encryption buffer length as
 	 * data_len + cipher_block_size - (data_len % cipher_block_size)
	 * To avoid integer overflow the following needs consideration:
	 *
	 * data_len % cipher_block_size can be at most cipher_block_size-1
 	 * which means that we are going to add at most 2*cipher_block_size - 1
	 * to data_len. So we need to check that data_len is at least 2 x
	 * cipher_block_size less than UINT_MAX to avoid overflow.
	 */
	if(UINT_MAX - data_len < 2 * cipher_block_size) {
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
				CIRON_OVERFLOW_ERROR, "Cannot unseal a buffer of size %ud due to integer overflow");
	}

	/* Taken from http://www.obviex.com/articles/ciphertextsize.aspx */
	*result_len = data_len + cipher_block_size - (data_len % cipher_block_size);
	return CIRON_OK;
}

/*
 * The layouts of the two functions below aims to show explicitly what is
 * being calculated. This isn't called often, so it is ok to not optimize
 * the calculations.
 */

CironError ciron_calculate_seal_buffer_length(CironContext context,  size_t data_len, size_t password_id_len, size_t *result_len) {

    CironError e;
	size_t encryption_buffer_length;
	if( (e = ciron_calculate_encryption_buffer_length(context, data_len,&encryption_buffer_length)) != CIRON_OK) {
	   return e;
	}

	size_t len = 6; /* MAC_PREFIIX */
	len++; /* delimiter */
	len += password_id_len;
	len++; /* delimiter */
	len = len + (NBYTES(context->encryption_options->salt_bits) * 2); /* Encryption salt (NBYTES * 2 due to hex encoding) */
	len++; /* delimiter */
	len += BASE64URL_ENCODE_SIZE(NBYTES(context->encryption_options->algorithm->iv_bits)); /* Base64url encoded IV */
	len++; /* delimiter */
	len += BASE64URL_ENCODE_SIZE(encryption_buffer_length); /* Base64url encoded encrypted data */
	len++; /* delimiter */
	len += NBYTES(context->integrity_options->salt_bits) * 2; /* Integrity salt (NBYTES * 2 due to hex encoding) */
	len++; /* delimiter */
	len += BASE64URL_ENCODE_SIZE(32); /* Base64url encoded HMAC (for HMAC SHA256 HMAC size is 32 bytes)  */
	/* see https://github.com/algermissen/ciron/issues/13 */
	*result_len = len;
	return CIRON_OK;
}

/*
 * Explanation of what is going on here is in ciron.h
 */
CironError ciron_calculate_unseal_buffer_length(CironContext context, size_t data_len, size_t *result_len) {

    int len;
    if(data_len > INT_MAX) {
        return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
    					CIRON_OVERFLOW_ERROR, "Data len %zu exceeds INT_MAX", data_len);
    }

	len = data_len;

	len -= 6; /* MAC_PREFIIX */
	len--; /* delimiter */
	/* We do not know password length when unsealing hence ignore it. If password is present, the calculated */
	/* buffer size will be this amount larger - which isn't a problem. */
	/* This fixes https://github.com/algermissen/ciron/issues/15 */
	len--; /* delimiter */
	len -= (NBYTES(context->encryption_options->salt_bits) * 2); /* Encryption salt (NBYTES * 2 due to hex encoding) */
	len--; /* delimiter */
	len -= BASE64URL_ENCODE_SIZE(NBYTES(context->encryption_options->algorithm->iv_bits)); /* Base64url encoded IV */
	len--; /* delimiter */
	/* We do not substract encryption size because this is what remains in the end and is the result */
	len--; /* delimiter */
	len -= (NBYTES(context->integrity_options->salt_bits) * 2); /* Integrity salt (NBYTES * 2 due to hex encoding) */
	len--; /* delimiter */
	len -= BASE64URL_ENCODE_SIZE(32); /* Base64url encoded HMAC (for HMAC SHA256 HMAC size is 32 bytes) */
	/* see https://github.com/algermissen/ciron/issues/13 */

	/*
	 * Now len is the length of the base64-encoded encrypted and we want the non-base64 encoded size:
	 */
	len = BASE64URL_DECODE_SIZE(len);

	/* Protect us against too small initial values. We cannot be less than 0 */
	if (len < 0) {
        return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
    					CIRON_OVERFLOW_ERROR, "Data len %zu too small", data_len);
	}
	*result_len = len;
	return CIRON_OK;
}

CironError ciron_seal(CironContext context, const unsigned char *data,
		size_t data_len, const unsigned char* password_id, size_t password_id_len,
		const unsigned char* password, size_t password_len,
		unsigned char *buffer_encrypted_bytes, unsigned char *result, size_t *plen) {

    CironOptions encryption_options;
    CironOptions integrity_options;


	CironError e;
	size_t prefix_len;
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

	encryption_options = context->encryption_options;
	integrity_options = context->integrity_options;

	/*
	 * Calculate number of salt bytes from provided options and
	 * verify that size is within limits.
	 */
	assert(NBYTES(encryption_options->salt_bits) <= MAX_SALT_BYTES);
	assert(NBYTES(integrity_options->salt_bits) <= MAX_SALT_BYTES);
	assert(NBYTES(encryption_options->algorithm->iv_bits) <= MAX_IV_BYTES);
	assert(NBYTES(encryption_options->algorithm->key_bits) <= MAX_KEY_BYTES);

	result_ptr = result;

	/*
	 * prefix*pwd*encSalt*iv64*data64* integritySalt*integrityHmac
	 */

	/*
	 * Write the prefix and delimiter.
	 * Advance the result pointer.
	 */
	prefix_len = strlen(MAC_PREFIX);
	memcpy(result_ptr, (unsigned char*) MAC_PREFIX "*", prefix_len+1);
	result_ptr += prefix_len + 1;

	/*
	 * If provided (len>0) write the password_id to the result_buffer
	 */
	if(password_id_len > 0) {
		memcpy(result_ptr, password_id, password_id_len);
		result_ptr += password_id_len;
	}

	/*
	 * Add a '*' delimiter.
	 */
	*result_ptr = DELIM;
	result_ptr++;



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
	 * With the base64 encoding of the encrypted data the HMAC base string
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
	 * (the base64url version is), we need an intermediate buffer to hold the binary.
	 * from which we generate the base64url encoded directly into the result.
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
		size_t data_len, CironPwdTable pwd_table, const unsigned char* password, size_t password_len,
		unsigned char *buffer_encrypted_bytes, unsigned char *result, size_t *plen) {
	CironOptions encryption_options;
	CironOptions integrity_options;

	CironError e;
	size_t i;
	int found_password;

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
	size_t data_remain_len;

	encryption_options = context->encryption_options;
    integrity_options = context->integrity_options;


	/*
	 * Calculate number of salt bytes from provided options and
	 * verify that size is within limits.
	 */
	assert(NBYTES(encryption_options->salt_bits) <= MAX_SALT_BYTES);
	assert(NBYTES(integrity_options->salt_bits) <= MAX_SALT_BYTES);
	assert(NBYTES(encryption_options->algorithm->iv_bits) <= MAX_IV_BYTES);
	assert(NBYTES(encryption_options->algorithm->key_bits) <= MAX_KEY_BYTES);

	/*
         * Prevent compiler warning about possible uninitialzed use.
         */
        memset(&encryption_iv_b64urlchars,0,sizeof(struct const_chars_and_len));
        memset(&encrypted_data_b64urlchars,0,sizeof(struct const_chars_and_len));

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
#if 0
	TRACE("data_remain_len=%d now prefix\n" _ data_remain_len);
#endif

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
	data_remain_len -= prefix.len;
	data_remain_len--;
#if 0
	TRACE("data_remain_len=%d now password_id\n" _ data_remain_len);
#endif
	/*
	 * Parse password_id sequence. There
	 * is no size checking here. it is the responsibility
	 * of the caller to supply the correct data_len value
	 * so that we do not read past the end of the sealed
	 * data.
	 */
	if ((e = parse(context, data_ptr, data_remain_len,
			&password_id) != CIRON_OK)) {
		return e;
	}

	/* Skip password and delimiter */
	data_ptr += password_id.len + 1;
	data_remain_len -= password_id.len;
	data_remain_len--;
#if 0
	TRACE("data_remain_len=%d now encryption salt\n" _ data_remain_len);
#endif

	if(password_id.len == 0 && password_len == 0) {
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
						CIRON_PASSWORD_ROTATION_ERROR, "Sealed token does not contain password ID and provided password is empty");
	}
	found_password = 0;
	if(pwd_table != NULL) {
		/*
		 * Now try to find the password in the password table and use that one if found.
		 * if we found one, we re-point the function parameters password and password len to
	 	 * the table entry.
	 	 */

		 for(i = 0; i < pwd_table->nentries; i++) {
			 CironPwdTableEntry entry = &(pwd_table->entries[i]);
			 if(entry->password_id_len != password_id.len) {
				 continue;
			 }
			 if(memcmp(entry->password_id,password_id.chars, password_id.len) != 0) {
				 continue;
			 }
			 password = entry->password;
			 password_len = entry->password_len;
			 found_password = 1;
			 break;
		 }
	}
	/*
	 * Right now, we accept if a password is not found in the table and fall back to the
	 * provided password if it has been provided. If none was provided, we report an error.
	 */
	if(( !found_password ) && (password_len == 0)) {
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
				CIRON_PASSWORD_ROTATION_ERROR, "Password with ID %.*s not found" , password_id.len, password_id.chars);
	}


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
	data_remain_len -= encryption_salt_hexchars.len;
	data_remain_len--;
#if 0
	TRACE("data_remain_len=%d now enc IV\n" _ data_remain_len);
#endif
	/*
	 * Parse encryption IV base64url sequence.
	 */
	if ((e = parse_max_len(context, data_ptr, data_remain_len, MAX_IV_B64URL_CHARS,
			&encryption_iv_b64urlchars) != CIRON_OK)) {
		return e;
	}
#if 0
	TRACE("len=%d\n" _ encryption_iv_b64urlchars.len);
	TRACE("s=%s\n" _ encryption_iv_b64urlchars.chars);
#endif

	/* Skip IV base64url and delimiter */
	data_ptr += encryption_iv_b64urlchars.len + 1;
	data_remain_len -= encryption_iv_b64urlchars.len;
	data_remain_len--;
#if 0
	TRACE("data_remain_len=%d now 64ofenced data\n" _ data_remain_len);
#endif

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
	data_remain_len -= encrypted_data_b64urlchars.len;
	data_remain_len--;
#if 0
	TRACE("data_remain_len=%d now hmac remains with this len\n" _ data_remain_len);
#endif

	/*
	 * Now we can set the HMAC base string length. We must
	 * substract one because we already advanced to the delimiter
	 * above. And the elimiter is not part of the base string.
	 */
	hmac_base_chars.len = data_ptr - data;
	hmac_base_chars.len--;

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
	data_remain_len -= integrity_salt_hexchars.len;
	data_remain_len--;
#if 0
	TRACE("data_remain_len=%d\n" _ data_remain_len);
#endif

	/*
	 * Now we parse the base64url encoded HMAC value.
	 * We do not need to parse for delimiter here, because it
	 * is the last portion of the input anyhow.
	 */
	integrity_hmac_b64urlchars.chars = data_ptr;
	integrity_hmac_b64urlchars.len = data_remain_len;
	if (integrity_hmac_b64urlchars.len > MAX_IV_B64URL_CHARS) {
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
				CIRON_TOKEN_PARSE_ERROR,
				"Base64url encoded string of HMAC is too long. Parsed %d bytes, but max is %d",
				integrity_hmac_b64urlchars.len, MAX_IV_B64URL_CHARS);
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
	if( (e = ciron_base64url_decode(context,integrity_hmac_b64urlchars.chars,
			integrity_hmac_b64urlchars.len,
			incodming_integrity_hmac_bytes.chars,
			&(incodming_integrity_hmac_bytes.len))) != CIRON_OK) {
		return e;
	}

	/*
	 * Lengths of the HMACs must match, of course.
	 */
	if (integrity_hmac_bytes.len != incodming_integrity_hmac_bytes.len) {
		return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
				CIRON_TOKEN_VALIDATION_ERROR,
				"HMAC signature invalid (lengths differ)");
	}

	/*
	 * And check for HMAC equality. If this succeeds, we know that no one has tampered
	 * with the input.
	 */
	if (! ciron_fixed_time_equal(incodming_integrity_hmac_bytes.chars, integrity_hmac_bytes.chars,
			integrity_hmac_bytes.len) ) {
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
	 * again here using the other macro. Try it -> FIXME. What did I actually mean here?
	 */
	encryption_iv_bytes.chars = buffer_encryption_iv_bytes;
	if( (e = ciron_base64url_decode(context,encryption_iv_b64urlchars.chars,
			encryption_iv_b64urlchars.len, encryption_iv_bytes.chars,
			&(encryption_iv_bytes.len))) != CIRON_OK) {
		return e;
	}

	/*
	 * Turn base64 of encrypted into bytes for decrypting. It is
	 * caller's responsibility that the buffer is large enough.
	 */
	encrypted_bytes.chars = buffer_encrypted_bytes;
	if( (e = ciron_base64url_decode(context,encrypted_data_b64urlchars.chars,
			encrypted_data_b64urlchars.len, encrypted_bytes.chars,
			&(encrypted_bytes.len))) != CIRON_OK) {
		return e;
	}

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
		size_t len, struct const_chars_and_len *balp) {
	size_t pos = 0;
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
		const unsigned char *data, size_t len, size_t expected_len,
		struct const_chars_and_len *balp) {
	size_t pos = 0;
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
		size_t len, size_t max_len, struct const_chars_and_len *balp) {
	size_t pos = 0;
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
