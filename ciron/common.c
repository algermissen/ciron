#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "ciron.h"
#include "common.h"

/* FIXME: docme, cleanme */

/**
 * Algorithms provided by ciron.
 *
 * If you add more algorithms here, you need to check and maybe adjust the
 * buffer size constants defined in common.h
 *
 * Also, you must add to the selection if-cascades in crypto_openssl.c for them
 * to be recognized.
 */
struct Algorithm _AES_128_CBC = { "aes-128-cbc", 128, 128 };
struct Algorithm _AES_256_CBC = { "aes-256-cbc", 256, 128 };
struct Algorithm _SHA_256 = { "sha256", 256, 0 };

Algorithm AES_128_CBC = &_AES_128_CBC;
Algorithm AES_256_CBC = &_AES_256_CBC;
Algorithm SHA_256 = &_SHA_256;

/** Default options provided by ciron.
 *
 * You must make sure that MAX_SALT_BYTES defined in common.h
 * matches the largest salt bit value defined by the options.
 *
 * There is currently no support for adding more options through
 * user code. This is an open issue:
 * https://github.com/algermissen/ciron/issues/2
 *
 *
 */
struct Options _DEFAULT_ENCRYPTION_OPTIONS = { 256, &_AES_256_CBC, 1 };
struct Options _DEFAULT_INTEGRITY_OPTIONS = { 256, &_SHA_256, 1 };

Options DEFAULT_ENCRYPTION_OPTIONS = &_DEFAULT_ENCRYPTION_OPTIONS;
Options DEFAULT_INTEGRITY_OPTIONS = &_DEFAULT_INTEGRITY_OPTIONS;

/** Error strings used by ciron_strerror
 *
 */
static const char *error_strings[] = {
		"No error", /* CIRON_OK */
		"Token parse error", /* CIRON_TOKEN_PARSE_ERROR */
		"Token invalid", /* CIRON_TOKEN_VALIDATION_ERROR */
		"Unknown algorithm", /* CIRON_ERROR_UNKNOWN_ALGORITHM */
		"Some unrecognized error in the crypto library occurred", /* CIRON_CRYPTO_ERROR */
		NULL
};

const char* ciron_strerror(CironError e) {
	assert(e >= 0 && e <= 0);
	return error_strings[e];
}

CironError ciron_set_error(CironContext ctx, const char *file, int line,
		unsigned long crypto_error, CironError e, const char *fmt, ...) {
	va_list args;
	char buf[256];
	va_start(args, fmt);
	vsnprintf(ctx->error_string, sizeof(ctx->error_string), fmt, args);
	va_end(args);
	if (crypto_error != NO_CRYPTO_ERROR) {
		snprintf(buf, sizeof(buf), " in %s, line %d (internal error:%ld)", file,
				line, crypto_error);
	} else {
		snprintf(buf, sizeof(buf), " in %s, line %d", file, line);
	}
	strncat(ctx->error_string, buf,
			sizeof(ctx->error_string) - strlen(ctx->error_string) - 1);
	ctx->error = e;
	ctx->crypto_error = crypto_error;
	return e;
}

const char *ciron_get_error(CironContext ctx) {
	return ctx->error_string;
}

CironError ciron_get_error_code(CironContext ctx) {
	return ctx->error;
}

/* Lookup 'table' for hex encoding */
static const char hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f' };
void ciron_bytes_to_hex(const unsigned char *bytes, int len, unsigned char *buf) {
	int j;
	for (j = 0; j < len; j++) {
		int v;
		v = bytes[j] & 0xFF;
		buf[j * 2] = hex[v >> 4];
		buf[j * 2 + 1] = hex[v & 0x0F];
	}
}

/** Tracing and assertion utilities below
 *
 */

int ciron_trace(const char * fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	return 0;
}

int ciron_trace_bytes(const char *name, const unsigned char *bytes, int len) {
	int i;
	fprintf(stderr, "Byte array %s: ", name);
	for (i = 0; i < len; i++) {
		fprintf(stderr, "%s0x%02x", (i == 0) ? "" : ",", bytes[i]);
	}
	fprintf(stderr, "\n");
	return 0;
}

void ciron_assert(const char *exp, const char *file, unsigned line) {
	fflush(NULL );
	fprintf(stderr, "\n\nAssertion \"%s\" failed in %s, line %u\n", exp, file,
			line);
	fflush(stderr);
	abort();
}

