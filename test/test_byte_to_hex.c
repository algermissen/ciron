#include "util.h"
#include "common.h"
#include "test.h"


int test_bytes_to_hex() {

	unsigned char buf[1024];
	unsigned char single0[1] = { 0 };
	unsigned char singleFF[1] = { 255 };
	unsigned char bytes[4] = { 10, 10, 10, 10 };
	unsigned char bytes2[4] = { 255, 0, 255, 0 };

	ciron_bytes_to_hex(bytes, 4, buf);
	EXPECT_BYTE_EQUAL((unsigned char *)"0a0a0a0a", buf,8);

	ciron_bytes_to_hex(single0, 1, buf);
	EXPECT_BYTE_EQUAL((unsigned char *)"00", buf,2);

	ciron_bytes_to_hex(singleFF, 1, buf);
	EXPECT_BYTE_EQUAL((unsigned char *)"ff", buf,2);

	ciron_bytes_to_hex(bytes2, 4, buf);
	EXPECT_BYTE_EQUAL((unsigned char *)"ff00ff00", buf,8);

	return 1;
}

/*

 Test vectors from http://www.ietf.org/rfc/rfc4648.txt section 10.

 BASE64("") = ""

 BASE64("f") = "Zg=="

 BASE64("fo") = "Zm8="

 BASE64("foo") = "Zm9v"

 BASE64("foob") = "Zm9vYg=="

 BASE64("fooba") = "Zm9vYmE="

 BASE64("foobar") = "Zm9vYmFy"
 */
#if 0
int test_ciron_base64_encode() {

	unsigned char *chars[256];
	int len;

	unsigned char b1[] = { 0x66 }; /* "f" */
	unsigned char b2[] = { 0x66, 0x6f }; /* "fo" */
	unsigned char b3[] = { 0x66, 0x6f, 0x6f }; /* "foo" */
	unsigned char b4[] = { 0x66, 0x6f, 0x6f, 0x62 }; /* "foob" */
	unsigned char b5[] = { 0x66, 0x6f, 0x6f, 0x62, 0x61 }; /* "fooba" */
	unsigned char b6[] = { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 }; /* "foobar" */

	ciron_base64_encode(b1, 0, chars, &len); /* Can't have empty bytes, so we just use len=0 to mimick */
	EXPECT_STR_EQUAL("", chars);
	ciron_base64_encode(b1, 1, chars, &len);
	EXPECT_STR_EQUAL("Zg==", chars);

	ciron_base64_encode(b2, 2, chars, &len);
	EXPECT_STR_EQUAL("Zm8=", chars);

	ciron_base64_encode(b3, 3, chars, &len);
	EXPECT_STR_EQUAL("Zm9v", chars);

	ciron_base64_encode(b4, 4, chars, &len);
	EXPECT_STR_EQUAL("Zm9vYg==", chars);

	ciron_base64_encode(b5, 5, chars, &len);
	EXPECT_STR_EQUAL("Zm9vYmE=", chars);

	ciron_base64_encode(b6, 6, chars, &len);
	EXPECT_STR_EQUAL("Zm9vYmFy", chars);

	return 1;
}
#endif
/*

 Test vectors from http://www.ietf.org/rfc/rfc4648.txt section 10.

 BASE64("") = ""

 BASE64("f") = "Zg=="

 BASE64("fo") = "Zm8="

 BASE64("foo") = "Zm9v"

 BASE64("foob") = "Zm9vYg=="

 BASE64("fooba") = "Zm9vYmE="

 BASE64("foobar") = "Zm9vYmFy"
 */
#if 0
int test_ciron_base64_decode() {

	unsigned char *bytes[256];
	int len;

	unsigned char b1[] = { 0x66 }; /* "f" */
	unsigned char b2[] = { 0x66, 0x6f }; /* "fo" */
	unsigned char b3[] = { 0x66, 0x6f, 0x6f }; /* "foo" */
	unsigned char b4[] = { 0x66, 0x6f, 0x6f, 0x62 }; /* "foob" */
	unsigned char b5[] = { 0x66, 0x6f, 0x6f, 0x62, 0x61 }; /* "fooba" */
	unsigned char b6[] = { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 }; /* "foobar" */

	ciron_base64_decode("", 0, bytes, &len);
	EXPECT_TRUE(len == 0);

	ciron_base64_decode("Zg==", 4, bytes, &len);
	EXPECT_TRUE(len == 1);
	EXPECT_BYTE_EQUAL(b1, bytes,1);

	ciron_base64_decode("Zm8=", 4, bytes, &len);
	EXPECT_TRUE(len == 2);
	EXPECT_BYTE_EQUAL(b2, bytes,2);

	ciron_base64_decode("Zm9v", 4, bytes, &len);
	EXPECT_TRUE(len == 3);
	EXPECT_BYTE_EQUAL(b3, bytes,3);

	ciron_base64_decode("Zm9vYg==", 8, bytes, &len);
	EXPECT_TRUE(len == 4);
	EXPECT_BYTE_EQUAL(b4, bytes,4);

	ciron_base64_decode("Zm9vYmE=", 8, bytes, &len);
	EXPECT_TRUE(len == 5);
	EXPECT_BYTE_EQUAL(b5, bytes,5);

	ciron_base64_decode("Zm9vYmFy", 8, bytes, &len);
	EXPECT_TRUE(len == 6);
	EXPECT_BYTE_EQUAL(b6, bytes,6);



	return 1;
}
#endif

int main(int argc, char **argv) {

	RUNTEST(argv[0],test_bytes_to_hex);
	/*
	TEST(test_ciron_base64_encode);
	TEST(test_ciron_base64_decode);
	*/

	return 0;
}
