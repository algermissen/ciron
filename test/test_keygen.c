#include "crypto.h"
#include "common.h"
#include "test.h"

/* Algorithm vars with key lengths of 20, 25, and 16 bytes for the tests. */
struct Algorithm Test20bytesKeyLen = { "not-needed", 160, 0 };
struct Algorithm Test25bytesKeyLen = { "not-needed", 200, 0 };
struct Algorithm Test16bytesKeyLen = { "not-needed", 128, 0 };

struct CironContext ctx;

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
int PBKDF2_HMAC_SHA1_Test_1() {
	unsigned char key[1024];
	const unsigned char *password = (unsigned char*)"password";
	const unsigned char salt[4] = { 's', 'a', 'l', 't' };
	const unsigned char expected[] = { 0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
			0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37,
			0xa6 };

	ciron_generate_key(&ctx,password, 8, salt, 4, &Test20bytesKeyLen, 1, key);
	EXPECT_BYTE_EQUAL(expected, key, 20);

	return 1;
}

/*
 * Input:
 P = "password" (8 octets)
 S = "salt" (4 octets)
 c = 2
 dkLen = 20

 Output:
 DK = ea 6c 01 4d c7 2d 6f 8c
 cd 1e d9 2a ce 1d 41 f0
 d8 de 89 57             (20 octets)
 *
 *
 */
int PBKDF2_HMAC_SHA1_Test_2() {
	unsigned char key[1024];
	const unsigned char *password = (unsigned char*)"password";
	const unsigned char salt[4] = { 's', 'a', 'l', 't' };
	const unsigned char expected[] = { 0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
			0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89,
			0x57 };

	ciron_generate_key(&ctx,password, 8, salt, 4, &Test20bytesKeyLen, 2, key);
	EXPECT_BYTE_EQUAL(expected, key, 20);

	return 1;
}

/*
 * Input:
 P = "password" (8 octets)
 S = "salt" (4 octets)
 c = 4096
 dkLen = 20

 Output:
 DK = 4b 00 79 01 b7 65 48 9a
 be ad 49 d9 26 f7 21 d0
 65 a4 29 c1             (20 octets)
 */
int PBKDF2_HMAC_SHA1_Test_3() {
	unsigned char key[1024];
	const unsigned char *password = (unsigned char *)"password";
	const unsigned char salt[4] = { 's', 'a', 'l', 't' };
	const unsigned char expected[] = { 0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
			0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29,
			0xc1 };

	ciron_generate_key(&ctx,password, 8, salt, 4, &Test20bytesKeyLen, 4096, key);
	EXPECT_BYTE_EQUAL(expected, key, 20);

	return 1;
}
/*
 * Input:
 P = "password" (8 octets)
 S = "salt" (4 octets)
 c = 16777216
 dkLen = 20

 Output:
 DK = ee fe 3d 61 cd 4d a4 e4
 e9 94 5b 3d 6b a2 15 8c
 26 34 e9 84             (20 octets)
 */
int PBKDF2_HMAC_SHA1_Test_4() {
	unsigned char key[1024];
	const unsigned char *password = (unsigned char *)"password";
	const unsigned char salt[4] = { 's', 'a', 'l', 't' };
	const unsigned char expected[] = { 0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4,
			0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c, 0x26, 0x34, 0xe9,
			0x84 };

	ciron_generate_key(&ctx,password, 8, salt, 4, &Test20bytesKeyLen, 16777216, key);
	EXPECT_BYTE_EQUAL(expected, key, 20);

	return 1;
}
/*
 * Input:
 P = "passwordPASSWORDpassword" (24 octets)
 S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
 c = 4096
 dkLen = 25

 Output:
 DK = 3d 2e ec 4f e4 1c 84 9b
 80 c8 d8 36 62 c0 e4 4a
 8b 29 1a 96 4c f2 f0 70
 38                      (25 octets)
 */
int PBKDF2_HMAC_SHA1_Test_5() {
	unsigned char key[1024];
	const unsigned char *pwd = (unsigned char *)"passwordPASSWORDpassword";
	const unsigned char slt[36] = { 's', 'a', 'l', 't', 'S', 'A', 'L', 'T', 's', 'a',
			'l', 't', 'S', 'A', 'L', 'T', 's', 'a', 'l', 't', 'S', 'A', 'L',
			'T', 's', 'a', 'l', 't', 'S', 'A', 'L', 'T', 's', 'a', 'l', 't' };
	const unsigned char expected[] = { 0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
			0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a, 0x8b, 0x29, 0x1a,
			0x96, 0x4c, 0xf2, 0xf0, 0x70, 0x38 };

	ciron_generate_key(&ctx,pwd, 24, slt, 36, &Test25bytesKeyLen, 4096, key);
	EXPECT_BYTE_EQUAL(expected, key, 25);

	return 1;
}
/*
 *    Input:
 P = "pass\0word" (9 octets)
 S = "sa\0lt" (5 octets)
 c = 4096
 dkLen = 16

 Output:
 DK = 56 fa 6a a7 55 48 09 9d
 cc 37 d7 f0 34 25 e0 c3 (16 octets)
 */
int PBKDF2_HMAC_SHA1_Test_6() {
	unsigned char key[1024];
	const unsigned char pwd[9] = { 'p', 'a', 's', 's', 0, 'w', 'o', 'r', 'd' };
	const unsigned char slt[5] = { 's', 'a', 0, 'l', 't' };
	const unsigned char expected[] = { 0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
			0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3 };

	ciron_generate_key(&ctx,pwd, 9, slt, 5, &Test16bytesKeyLen, 4096, key);
	EXPECT_BYTE_EQUAL(expected, key, 16);

	return 1;
}

/*
 * These tests the key generation functions, using the test cases provided in
 * http://tools.ietf.org/html/rfc6070
 */
int main(int argc, char **argv) {
	RUNTEST(argv[0],PBKDF2_HMAC_SHA1_Test_1);
	RUNTEST(argv[0],PBKDF2_HMAC_SHA1_Test_2);
	RUNTEST(argv[0],PBKDF2_HMAC_SHA1_Test_3);
	/* too slow this test is.
	RUNTEST(argv[0],PBKDF2_HMAC_SHA1_Test_4);
	*/
	RUNTEST(argv[0],PBKDF2_HMAC_SHA1_Test_5);
	RUNTEST(argv[0],PBKDF2_HMAC_SHA1_Test_6);
	return 0;
}
