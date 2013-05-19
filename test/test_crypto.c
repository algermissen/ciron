#include "crypto.h"
#include "common.h"
#include "test.h"

const unsigned char *password = (unsigned char *)"password";
const unsigned char salt[4] = { 's', 'a', 'l', 't' };

/* Algorithms with a key length of 20, 25, and 16 bytes */
struct Algorithm Test20bytesKeyLen = { "not-needed", 160, 0 };
struct Algorithm Test25bytesKeyLen = { "not-needed", 200, 0 };
struct Algorithm Test16bytesKeyLen = { "not-needed", 128, 0 };

struct CironContext ctx;
/*
 * These tests the key generation functions, using the test cases provided in
 * http://tools.ietf.org/html/rfc6070
 */
int main(int argc, char **argv) {
/*
	unsigned char salt_buf[32];
	*/
	unsigned char buf[1024];
	unsigned char sbuf[1024];
	unsigned char bbuf[1024];
	int i;

	bzero(buf, sizeof(buf));

	bzero(sbuf, sizeof(sbuf));
	bzero(bbuf, sizeof(bbuf));

	ciron_generate_salt(&ctx,32, buf);

	for (i = 0; i < strlen((char*)buf); i++) {
		sbuf[i] = buf[i];
	}

	ciron_generate_key(&ctx,(unsigned char *)"password",  8, sbuf, strlen((char*)buf),
			DEFAULT_ENCRYPTION_OPTIONS->algorithm, 1, bbuf);

	strcpy((char*)buf, "salt");

	for (i = 0; i < 4; i++) {
		sbuf[i] = buf[i];
	}

	ciron_generate_key(&ctx,(unsigned char *)"password",  8, sbuf, strlen((char*)buf), &Test20bytesKeyLen, 1,
			bbuf);


	return 0;

}

/*
 * This tests the key generation functions, using the test cases provided in
 * http://tools.ietf.org/html/rfc6070
 *
 * Input:
 *     P = "password" (8 octets)
 *     S = "salt" (4 octets)
 *     c = 1
 *     dkLen = 20
 *
 *    Output:
 *     DK = 0c 60 c8 0f 96 1f 0e 71
 *           f3 a9 b5 24 af 60 12 06
 *           2f e0 37 a6             (20 octets)
 */
int test_seal() {
	unsigned char key[1024];
	const unsigned char expected[] = { 0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
			0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37,
			0xa6 };

	ciron_generate_key(&ctx,password,8, salt, 4, &Test20bytesKeyLen, 1, key);
	EXPECT_BYTE_EQUAL(expected, key, 20);

	return 1;
}
