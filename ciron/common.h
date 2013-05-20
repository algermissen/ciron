#ifndef COMMON_H
#define COMMON_H 1
#include <ctype.h>
#include <math.h>
#include "config.h"
#include "ciron.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The following macros define buffer size constants.
 *
 * These constants are defined for convenience, to allow
 * the callers of functions that require caller-buffer-allocation
 * to use fixed buffers as opposed to dealing with dynamic
 * allocation and deallocation of memory.
 *
 * The buffer sizes are considerably small to justify the
 * space overhead.
 *
 * These buffer sizes depend on the algorithms and options defined
 * in common.c and must be adjusted if new algorithms are added that
 * require increased buffer sizes.
 *
 */

/** Maximum size of salt values.
 *
 * MAX_SALT_BYTES must match the largest salt_bits / 8 of all options
 * supplied.
 *
 * Note that the salts actually generated will be twice as long as this
 * constant due to the hex-encoding.
 */
#define MAX_SALT_BYTES 32


/** Must match the requirements by the supplied algorithms. For CBC algorithms
 * it is always 128 bit.
 */
#define MAX_IV_BYTES 32


/** Maximum size necessary for storing IVs in base64url encoded form.
 *
 * Depends on MAX_IV_BYTES and amounts to ceil( MAX_IV_BYTES * 4/3 )
 *
 */
#define MAX_IV_B64CHARS 44 /* FIXME: try with 43, wich would be the correct value */

/* Maximum size of keys used.
 *
 * Must match the requirements of the supplied algorithms.
 *
 */
#define MAX_KEY_BYTES 32

/*
 * Must match the specifications of the supplied HMAC algorithms.
 *
 */
#define MAX_HMAC_BYTES 32

/*
 * This is arbitrarily chosen
 */
/*
#define MAX_PASSWORD_BYTES 256
*/

/** A macro to calculate byte size from number of bits.
 *
 */
#define NBYTES(bits) (ceil((double) (bits) / 8) )

/** A macro for calculated the maximal size of
 * a base64url encoding of a char array of length n.
 */
#define BASE64URL_ENCODE_SIZE(n) (ceil( (double)( (n) * 4) / 3))

/** A macro for calculated the maximal size of
 * a decoding of a base64url encoded char array
 * of length n.
 */
#define BASE64URL_DECODE_SIZE(n) (floor((double) ( (n) * 3) / 4))


/** Structure for the Algorithm typedef in ciron.h
 */
struct Algorithm {
	const char* name;
	int key_bits;
	int iv_bits;
};

/** Structure for the Options typedef in ciron.h
 */
struct Options {
	int salt_bits;
	Algorithm algorithm;
	int iterations;
};


/**
 * Mocro used to supply a value for cases where an error is a ciron-level
 * error and not one of the underlying crypto library.
 *
 */
#define NO_CRYPTO_ERROR 0

/**
 * Set the context error for error retrieval by the caller.
 */
CironError CIRONAPI ciron_set_error(CironContext ctx, const char *file, int line, unsigned long crypto_error,CironError e, const char *fmt, ...);


/** Turn an unsigned char array into an array of hex-encoded bytes.
 *
 * The result will encode each bye as a two-chars hex value (00 to ff)
 * and thus be twice as long as the input.
 *
 * The caller is responsible to provide a buffer of at least 2xlen
 * bytes to hold the result.
 *
 * Does not \0 terminate the created string.
 */
void CIRONAPI ciron_bytes_to_hex(const unsigned char *bytes, int len, unsigned char *buf);



/** The remainder of this header file defines utilities for
 * tracing and assertions thathave been used throughout development and
 * debugging.
 */

int CIRONAPI ciron_trace_bytes(const char *name, const unsigned char *bytes, int len);

#ifndef NDEBUG
#  undef _
#  define _ ,
#  define TRACE(FMT) do { ciron_trace(FMT); } while (0)
   int CIRONAPI ciron_trace(const char * fmt, ...);
#else
#  define TRACE(FMT)     /* empty */
   /* no prototype for ciron_trace() ! */
#endif /* !NDEBUG */



/* Uncomment this and '#ifdef 0' the code below to
 *   use C STDLIB assertions.
 * include <assert.h>
 */

#ifdef assert
#undef assert
#endif

void CIRONAPI ciron_assert(const char*,const char *,unsigned);

#define assert(f) \
   	do { \
   		if(f) {} \
   		else ciron_assert(#f,__FILE__,__LINE__); \
   	} while(0);


#ifdef __cplusplus
} // extern "C"
#endif


#endif /* !defined COMMON_H */
 
