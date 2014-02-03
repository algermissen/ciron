/*
 * Header file for ciron.
 *
 * This header file is all you need to include to use ciron
 * functionality from outside the ciron library.
 */
#ifndef CIRON_H
#define CIRON_H 1

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CIRONAPI
#define CIRONAPI
#endif

typedef struct CironOptions *CironOptions;
typedef struct CironAlgorithm *CironAlgorithm;

/** The algorithms and options defined by ciron.
 *
 * Please refer to common.c for their definition.
 */
extern CironAlgorithm CIRON_AES_128_CBC;
extern CironAlgorithm CIRON_AES_256_CBC;
extern CironAlgorithm CIRON_SHA_256;
extern CironOptions CIRON_DEFAULT_ENCRYPTION_OPTIONS;
extern CironOptions CIRON_DEFAULT_INTEGRITY_OPTIONS;


/** ciron error codes
 * 
 */
typedef enum {
	CIRON_OK, /* no error */
	CIRON_TOKEN_PARSE_ERROR, /* Token parse error */
	CIRON_TOKEN_VALIDATION_ERROR, /* Token cannot be validated */
	CIRON_PASSWORD_ROTATION_ERROR, /* Password rotation error */
	CIRON_ERROR_UNKNOWN_ALGORITHM, /* Unknown algorithm */
	CIRON_CRYPTO_ERROR, /* Some unrecognized error in the crypo library ocurred */
	CIRON_BASE64_ERROR /* Unexpected string length or padding in base64 en- or decoding */
	/* If you add errors here, add them in common.c also */
} CironError;

/** Obtain human readable string for the provided error code.
 *
 */
const char* CIRONAPI ciron_strerror(CironError e);



/** A handle for passing information between calls to ciron functions.
 *
 * Primarily used for propagating errors up the call-chain.
 * 
 * The struct is exposed so that API users can declare a local
 * variable of type 'struct CironContext' instead of having 
 * to allocate (and manage freeing) one. Althogh the exposure
 * makes it possible to access the fields directly, you
 * should use the accessor functions below.
 */
typedef struct CironContext {
	/** Ciron error code */
	CironError error;
	/** Error message providing specific error condition details */
	char error_string[1024];
	/** Error code of underlying crypto library, or 0 if not applicable */
	unsigned long crypto_error;
} *CironContext;

/*
 * Entry structure for password_id/password tables to support password rotation.
 */
typedef struct CironPwdTableEntry {
	int password_id_len;
	int password_len;
	unsigned char *password_id;
	unsigned char *password;
} *CironPwdTableEntry;

typedef struct CironPwdTable {
	int nentries;
	struct CironPwdTableEntry *entries;
} *CironPwdTable;


/** Get a human readable message about the last error
 * condition that ocurred for the given context.
 *
 */
const char * CIRONAPI ciron_get_error(CironContext ctx);

/** Get the ciron error code that occurred last in the
 * given context.
 *
 */
CironError CIRONAPI ciron_get_error_code(CironContext ctx);

/** Get the error code reported by the underlying
 * crypto library. Returns the code or NO_CRYPTO_ERROR if not
 * applicable in a given error case.
 */
unsigned long CIRONAPI ciron_get_crypto_error(CironContext ctx);


/** Calculates the required length for holding the encrypted
 * or decrypted version of data of the supplied length data_len.
 *
 * The supplied encryption options determine the actual length
 * required.
 *
 * ciron requires API users to provide the encryption buffer in
 * order to avoid memory allocations inside the API functions. 
 * 
 * For encryption algorithms that use block ciphers (all of
 * the algorithms of ciron currently are of this category) the
 * encryption buffer will be at most one block size larger
 * than the data to be encrypted.
 *
 * The reason that there is no corresponding method for 
 * calculating the size of the decryption buffer is that
 * the size calculated by calculate_encryption_buffer_length
 * is suitable for both contexts.
 *
 */
int CIRONAPI ciron_calculate_encryption_buffer_length(CironOptions encryption_options, int data_len);

/** Calculate the buffer size needed to store the sealed result
 * of unsealed data of the supplied length.
 *
 * This function calculates the sum of all the fields of the
 * resulting encapsulated token. The only field that varies in
 * size depending on the length of the input data is the
 * encryption result. The relationship is linear, so adding X
 * bytes to the input data will only add about X bytes to the
 * encapsulated token. Increase of the result size will be
 * in multiples of the cipher block size.
 *
 */
int CIRONAPI ciron_calculate_seal_buffer_length(CironOptions encryption_options, CironOptions integrity_options,int data_len, int password_id_len);

/** Calculate the buffer size needed to store the unsealed
 * result of sealed data of the supplied length.
 *
 * This works much like the corresponding function above for
 * calculating seal result buffer size. The difference is that
 * this function substracts the lengths of the individual
 * token components until the size of the unencrypted,
 * unsealed data remains.
 *
 */
int CIRONAPI ciron_calculate_unseal_buffer_length(CironOptions encryption_options, CironOptions integrity_options,int data_len, int password_id_len);

/** Seal the supplied data.
 *
 * This function seals the supplied data. The parameters are:
 *
 * - ctx: The CironContext to use, e.g for obtaining error
 *   message.
 * - data: The data to seal.
 * - data_len: The length of the data to seal.
 * - password_id: ID of the supplied password for password rotation
 * - password_id_len: The length of the password_id
 * - password: The password to use for sealing. Note that there
 *   will be no copy made of this data inside ciron. If you intend
 *   to prevent the password memory from being paged to disk, you
 *   need not be concerned about the internals of ciron.
 * - password_len: The length of the password.
 * - encryption_options: Options to use for encryption phase.
 * - integrity_options: Options to use for ensuring integrity.
 * - buffer_encrypted_bytes: Buffer of sufficient size to store
 *   the encrypted form of the supplied data. ciron provides
 *   the function 'calculate_encryption_buffer_length()' for
 *   calculating that size based on the data length.
 * - buf: Buffer of sufficient size to hold the encapsulated
 *   token. ciron provides the function 'calculate_seal_buffer_length'
 *   to calculate that size based on the data length.
 * - plen: Pointer to an integer in which ciron will
 *   store the actual length of the generated encapsulated token.
 */
CironError CIRONAPI ciron_seal(CironContext ctx,const unsigned char *data, int data_len, const unsigned char* password_id,
		int password_id_len,const unsigned char* password,
		int password_len, CironOptions encryption_options, CironOptions integrity_options, unsigned char *buffer_encrypted_bytes, unsigned char *buf, int *plen);

/** Unseal the supplied data.
 *
 * This function unseals the supplied data. The parameters are:
 *
 * - ctx: The CironContext to use, e.g for obtaining error
 *   message.
 * - data: The data to unseal.
 * - data_len: The length of the data to unseal.
 * - pwd_table: Table of password IDs and passwords for password rotation.
 * - password: The password to use for unsealing. Note that there
 *   will be no copy made of this data inside ciron. If you intend
 *   to prevent the password memory from being paged to disk, you
 *   need not be concerned about the internals of ciron.
 * - password_len: The length of the password.
 * - encryption_options: Options to use for encryption phase.
 * - integrity_options: Options to use for ensuring integrity.
 * - buffer_encrypted_bytes: Buffer of sufficient size to store
 *   the encrypted form of the encrypted data. ciron provides
 *   the function 'calculate_encryption_buffer_length()' for
 *   calculating that size based on the data length.
 * - buf: Buffer of sufficient size to hold the unsealed original
 *   data. ciron provides the function 'calculate_unseal_buffer_length'
 *   to calculate that size based on the data length.
 * - plen: Pointer to an integer in which ciron will
 *   store the actual length of the unsealed result.
 *
 * This function also performs token integrity validation and returns
 * and error if the token signature cannot be verified or the data
 * cannot be encrypted.
 */

CironError CIRONAPI ciron_unseal(CironContext ctx,const unsigned char *data, int data_len,
		CironPwdTable pwd_table,
		const unsigned char* password, int password_len, CironOptions encryption_options,
		CironOptions integrity_options, unsigned char *buffer_encrypted_bytes,unsigned char *result, int *plen);




#ifdef __cplusplus
} // extern "C"
#endif

#endif /* !defined CIRON_H */

