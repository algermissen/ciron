#include "crypto.h"
#include "common.h"
#include "ciron.h"
#include "test.h"

const unsigned char PASSWORD[] = { 0x73, 0x65, 0x6B, 0x79, 0x6F, 0x7A, 0x50, 0x5A };
const int PASSWORD_LEN = 8;

#define SALT_NBYTES  32
#define KEY_NBYTES  32
#define IV_NBYTES  16

#define SALT_NBYTESx2  64
#define SALT_NCHARS_0  65

struct CironContext ctx;

int test_encrypt_1() {

	const unsigned char data[] = { 0x44, 0x45, 0x46, 0x47, 0x48 };
	const int data_len = 5;
	const int ITERATIONS = 1;

	unsigned char salt_chars[SALT_NCHARS_0];
	unsigned char salt_bytes[SALT_NBYTESx2];
	unsigned char key_bytes[KEY_NBYTES];
	unsigned char iv_bytes[IV_NBYTES];

	unsigned char encrypted_bytes[1024];
	int encrypted_len;
	unsigned char decrypted_bytes[1024];
	int decrypted_len;


	ciron_generate_salt(&ctx,SALT_NBYTES, salt_chars);
	ciron_generate_key(&ctx,PASSWORD, PASSWORD_LEN, salt_bytes, SALT_NBYTES * 2,
			AES_256_CBC, ITERATIONS, key_bytes);
	ciron_generate_iv(&ctx,IV_NBYTES, iv_bytes);

	ciron_encrypt(&ctx,AES_256_CBC, key_bytes, iv_bytes, data, data_len,
			encrypted_bytes, &encrypted_len);

	ciron_decrypt(&ctx,AES_256_CBC, key_bytes, iv_bytes, encrypted_bytes, encrypted_len,
			decrypted_bytes, &decrypted_len);



	return 1;
}

/*
 * These tests the key generation functions, using the test cases provided in
 * http://tools.ietf.org/html/rfc6070
 */
int main(int argc, char **argv) {
	RUNTEST(argv[0],test_encrypt_1);
	return 0;
}

