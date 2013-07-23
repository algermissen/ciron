#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ciron.h"
#include "test.h"

#define MAXBUF 4096

struct CironContext ctx;

unsigned char cryptbuf[MAXBUF];
unsigned char sealbuf[MAXBUF];

const unsigned char password[] = { 's' , 'e' , 'c' , 'r' , 'e' , 't'};
const int password_len = 6;

int test_length_of_sealed() {
	CironOptions encryption_options = CIRON_DEFAULT_ENCRYPTION_OPTIONS;
	CironOptions integrity_options = CIRON_DEFAULT_INTEGRITY_OPTIONS;
	const unsigned char data[] = { 'T','e','s','t'};
	int data_len = 4;
	int result_len;

	if ((ciron_seal(&ctx, data, data_len, password, password_len,
			encryption_options, integrity_options, cryptbuf, sealbuf,
			&result_len)) != CIRON_OK) {
		fprintf(stderr, "Unable to seal: %s\n", ciron_get_error(&ctx));
		return 0;
	}
	EXPECT_INT_EQUAL(227, result_len);

	return 0;
}


int test_unseal_ok() {
	CironOptions encryption_options = CIRON_DEFAULT_ENCRYPTION_OPTIONS;
	CironOptions integrity_options = CIRON_DEFAULT_INTEGRITY_OPTIONS;
	const unsigned char expected[] = { 'T','e','s','t'};
	unsigned char *data =
			(unsigned char *) "Fe26.1**631b0bba26b306c9803ae7509816fa08905f9827bc4eec0517c93e5772e49d2c*hMXUUOqIlobjwLVgc0Xm7Q*P-bwmfd6vOwkjsB2k4neLQ*3a14c99729334d3e9384f2636913f92da6b583db6251530852ec31640fd1d654*Rzuqqx9QIw3MDrTW3muP2aWVahdZoTSAXucYnmrj16U";
	int data_len = 227;
	int result_len;

	if ((ciron_unseal(&ctx, data, data_len, password, password_len,
			encryption_options, integrity_options, cryptbuf, sealbuf,
			&result_len)) != CIRON_OK) {
		fprintf(stderr, "Unable to unseal: %s\n", ciron_get_error(&ctx));
		return 0;
	}
	EXPECT_INT_EQUAL(4, result_len);
	EXPECT_BYTE_EQUAL(expected, sealbuf,result_len);

	return 0;
}
int test_unseal_ok2() {
	CironOptions encryption_options = CIRON_DEFAULT_ENCRYPTION_OPTIONS;
	CironOptions integrity_options = CIRON_DEFAULT_INTEGRITY_OPTIONS;
	const unsigned char pwd[] = { 'x' , 'x' , 'x' };
	const int pwd_len = 3;

	const unsigned char expected[] = { 't','e','s','t' , '\0'};
	unsigned char *data =
			(unsigned char *) "Fe26.1**9de0940934c1939a73369190e7be392941e1b92026fa504226e566dac83c021d*1tvXFomFhdK4gDksQLqMSw*olYIJnS16-Ce-GQyS6kS-w*790b9fd88300110fb1fc7d2ac8118754a74ebb267ca80483414c1957ed4d9b52*4jB5Ctqs5C5fwyUEA_wip8mmb5J06DuJnsIQCeh7iHI";
	int data_len = 227;
	int result_len;

	if ((ciron_unseal(&ctx, data, data_len, pwd, pwd_len,
			encryption_options, integrity_options, cryptbuf, sealbuf,
			&result_len)) != CIRON_OK) {
		fprintf(stderr, "Unable to unseal: %s\n", ciron_get_error(&ctx));
		return 0;
	}
	EXPECT_INT_EQUAL(5, result_len);
	EXPECT_BYTE_EQUAL(expected, sealbuf,result_len);

	return 0;
}
int test_unseal_fails_on_invalid_prefix() {
	CironError e;
	CironOptions encryption_options = CIRON_DEFAULT_ENCRYPTION_OPTIONS;
	CironOptions integrity_options = CIRON_DEFAULT_INTEGRITY_OPTIONS;
	unsigned char *data =
			(unsigned char *) "Fe26.2**631b0bba26b306c9803ae7509816fa08905f9827bc4eec0517c93e5772e49d2c*hMXUUOqIlobjwLVgc0Xm7Q*P-bwmfd6vOwkjsB2k4neLQ*3a14c99729334d3e9384f2636913f92da6b583db6251530852ec31640fd1d654*Rzuqqx9QIw3MDrTW3muP2aWVahdZoTSAXucYnmrj16U";
	int data_len = 227;
	int result_len;

	if ((e = ciron_unseal(&ctx, data, data_len, password, password_len,
			encryption_options, integrity_options, cryptbuf, sealbuf,
			&result_len)) != CIRON_OK) {
		EXPECT_TRUE(e == CIRON_TOKEN_PARSE_ERROR);
		return 0;
	}
	return 0;
}
int test_unseal_fails_on_invalid_hmac() {
	CironError e;
	CironOptions encryption_options = CIRON_DEFAULT_ENCRYPTION_OPTIONS;
	CironOptions integrity_options = CIRON_DEFAULT_INTEGRITY_OPTIONS;
	unsigned char *data =
			(unsigned char *) "Fe26.1**631b0bba26b306c9803ae7509816fa08905f9827bc4eec0517c93e5772e49d2c*hMXUUOqIlobjwLVgc0Xm7Q*P-bwmfd6vOwkjsB2k4neLQ*3a14c99729334d3e9384f2636913f92da6b583db6251530852ec31640fd1d654*Rzuqqx9QIw3MDrTW3muP2aWVahdZoTSAXucYnmrj16x";
	int data_len = 227;
	int result_len;

	if ((e = ciron_unseal(&ctx, data, data_len, password, password_len,
			encryption_options, integrity_options, cryptbuf, sealbuf,
			&result_len)) != CIRON_OK) {
		EXPECT_TRUE(e == CIRON_TOKEN_VALIDATION_ERROR);
		return 0;
	}
	return 0;
}
int test_unseal_fails_on_wrong_password() {
	CironError e;
	CironOptions encryption_options = CIRON_DEFAULT_ENCRYPTION_OPTIONS;
	CironOptions integrity_options = CIRON_DEFAULT_INTEGRITY_OPTIONS;
	unsigned char *data =
			(unsigned char *) "Fe26.1**631b0bba26b306c9803ae7509816fa08905f9827bc4eec0517c93e5772e49d2c*hMXUUOqIlobjwLVgc0Xm7Q*P-bwmfd6vOwkjsB2k4neLQ*3a14c99729334d3e9384f2636913f92da6b583db6251530852ec31640fd1d654*Rzuqqx9QIw3MDrTW3muP2aWVahdZoTSAXucYnmrj16U";
	int data_len = 227;
	int result_len;

	if ((e = ciron_unseal(&ctx, data, data_len, password, password_len-1,
			encryption_options, integrity_options, cryptbuf, sealbuf,
			&result_len)) != CIRON_OK) {
		EXPECT_TRUE(e == CIRON_TOKEN_VALIDATION_ERROR);
		return 0;
	}
	return 0;
}
int test_unseal_iron_token_ok() {
	CironOptions encryption_options = CIRON_DEFAULT_ENCRYPTION_OPTIONS;
	CironOptions integrity_options = CIRON_DEFAULT_INTEGRITY_OPTIONS;
	const unsigned char *expected = (unsigned char *)"{\"a\":1,\"b\":2,\"c\":[3,4,5],\"d\":{\"e\":\"f\"}}";
	const unsigned char pwd[] = { 's' , 'o' , 'm' , 'e' , '_' , 'n','o','t','_','r','a','n','d','o','m','_','p','a','s','s','w','o','r','d'};
	const int pwd_len = 24;
	unsigned char *data =
			(unsigned char *)"Fe26.1**f9eebba02da4315acd770116b07a32aa4e7a7fe5fa89e0b89d2157c5d05891ef*_vDwAc4vMs448xng9Xgc2g*lc48O_ArSZlw3cGHkYKEH0XWHimPPQV9V52vPEimWgs2FHxyoAS5gk1W20-QHrIA*4a4818478f2d3b12536d4f0844ecc8c37d10e99b2f96bd63ab212bb1dc98aa3e*S-LG1fLECD_I2Pw2TsIXosc8fhKEsjil54ifAfEv5Xw";

	int data_len = 269;
	int result_len;

	if ((ciron_unseal(&ctx, data, data_len, pwd, pwd_len,
			encryption_options, integrity_options, cryptbuf, sealbuf,
			&result_len)) != CIRON_OK) {
		fprintf(stderr, "Unable to unseal: %s\n", ciron_get_error(&ctx));
		return 0;
	}
	/*
	sealbuf[result_len] = '\0';
	fprintf(stderr,"%s",sealbuf);
	*/
	EXPECT_INT_EQUAL((int)strlen((char*)expected), result_len);
	EXPECT_BYTE_EQUAL(expected, sealbuf,result_len);

	return 0;
}


int main(int argc, char **argv) {
	RUNTEST(argv[0], test_length_of_sealed);
	RUNTEST(argv[0], test_unseal_ok);
	RUNTEST(argv[0], test_unseal_ok2);
	RUNTEST(argv[0], test_unseal_fails_on_invalid_prefix);
	RUNTEST(argv[0], test_unseal_fails_on_invalid_hmac);
	RUNTEST(argv[0], test_unseal_fails_on_wrong_password);
	RUNTEST(argv[0], test_unseal_iron_token_ok);
	return 0;
}
