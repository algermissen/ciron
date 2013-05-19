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

typedef struct Options *Options;
typedef struct Algorithm *Algorithm;

/** The algorithms and options defined by ciron.
 *
 * Please refer to common.c for their definition.
 */
extern Algorithm AES_128_CBC;
extern Algorithm AES_256_CBC;
extern Algorithm SHA_256;
extern Options DEFAULT_ENCRYPTION_OPTIONS;
extern Options DEFAULT_INTEGRITY_OPTIONS;


/** ciron error codes
 *
 */
typedef enum {
	CIRON_OK, /* no error */
	CIRON_TOKEN_PARSE_ERROR, /* Token parse error */
	CIRON_TOKEN_VALIDATION_ERROR, /* Token cannot be validated */
	CIRON_ERROR_UNKNOWN_ALGORITHM, /* Unknown algorithm */
	CIRON_CRYPTO_ERROR /* Some unrecognized error in the crypo library ocurred */
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
 */
typedef struct CironContext {
	/** Ciron error code */
	CironError error;
	/** Error message providing specific error condition details */
	char error_string[1024];
	/** Error code of underlying crypto library, or 0 if not applicable */
	unsigned long crypto_error;
} *CironContext;

/** Get a human readable message about the error condition.
 *
 */
const char * CIRONAPI ciron_get_error(CironContext ctx);

/** Get the ciron error code that occurred last.
 *
 */
CironError CIRONAPI ciron_get_error_code(CironContext ctx);

/** Get the error code reproted by the underlying
 * crypto library. Returns the code or 0 if not
 * applicable in this error case.
 */
unsigned long CIRONAPI ciron_get_crypto_error(CironContext ctx);


/** Calculates the required length for holding the encrypted version of
 * data of the supplied length data_len.
 *
 * The sypplied encryption options determine the actual length required.
 *
 */
int CIRONAPI calculate_encryption_buffer_length(Options encryption_options, int data_len);

/** Calculate the buffer size needed to store the sealed result of unsealed
 * data of the supplied length.
 *
 */
int CIRONAPI calculate_seal_buffer_length(Options encryption_options, Options integrity_options,int data_len);

/** Calculate the buffer size needed to store the unsealed result of sealed
 * data of the supplied length.
 *
 */
int CIRONAPI calculate_unseal_buffer_length(Options encryption_options, Options integrity_options,int data_len);

/** Seal the supplied data.
 *
 * Details pending. Please refer to iron/iron.c.
 */
CironError CIRONAPI ciron_seal(CironContext ctx,const unsigned char *data, int data_len, const unsigned char* password,
		int password_len, Options encryption_options, Options integrity_options, unsigned char *buffer_encrypted_bytes, unsigned char *buf, int *plen);

/** Unseal the supplied data.
 *
 * Details pending. Please refer to iron/iron.c.
 */
CironError CIRONAPI ciron_unseal(CironContext ctx,const unsigned char *data, int data_len,
		const unsigned char* password, int password_len, Options encryption_options,
		Options integrity_options, unsigned char *buffer_encrypted_bytes,unsigned char *result, int *plen);




#ifdef __cplusplus
} // extern "C"
#endif

#endif /* !defined CIRON_H */

