#include "crypto.h"
#include "common.h"
#include "test.h"

struct CironContext ctx;

int test_that_keygen_generates_same_key() {

	unsigned char buf1[1024];
	unsigned char buf2[1024];
	unsigned char saltbuf[1024];

	ciron_generate_salt(&ctx,32, saltbuf);

	ciron_generate_key(&ctx,(unsigned char *)"password",  8, saltbuf, 64,
			CIRON_DEFAULT_ENCRYPTION_OPTIONS->algorithm, 1, buf1);

	ciron_generate_key(&ctx,(unsigned char *)"password",  8, saltbuf, 64,
			CIRON_DEFAULT_ENCRYPTION_OPTIONS->algorithm, 1, buf2);

	EXPECT_BYTE_EQUAL(buf1, buf2, NBYTES(CIRON_DEFAULT_ENCRYPTION_OPTIONS->algorithm->key_bits));

	return 0;
}

int main(int argc, char **argv) {
	RUNTEST(argv[0],test_that_keygen_generates_same_key);
	return 0;
}
