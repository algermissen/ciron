/*
 This file is based on base64 encode/decode code from
 https://github.com/superwills/NibbleAndAHalf.

 The code organization has been slightly modifies to match me own file structure.

 Original License of the base64 code below.

 https://github.com/superwills/NibbleAndAHalf
 base64.h -- Fast base64 encoding and decoding.
 version 1.0.0, April 17, 2013 143a

 Copyright (C) 2013 William Sherif

 This software is provided 'as-is', without any express or implied
 warranty.  In no event will the authors be held liable for any damages
 arising from the use of this software.

 Permission is granted to anyone to use this software for any purpose,
 including commercial applications, and to alter it and redistribute it
 freely, subject to the following restrictions:

 1. The origin of this software must not be misrepresented; you must not
 claim that you wrote the original software. If you use this software
 in a product, an acknowledgment in the product documentation would be
 appreciated but is not required.
 2. Altered source versions must be plainly marked as such, and must not be
 misrepresented as being the original software.
 3. This notice may not be removed or altered from any source distribution.

 William Sherif
 will.sherif@gmail.com

 YWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVz

 #include <stdlib.h>
 */
#include "base64url.h"
#include "common.h"

const static unsigned char* b64 =
		(unsigned char *) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* maps A=>0,B=>1.. */
const static unsigned char unb64[]={
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* 10 */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* 20 */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* 30 */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* 40 */
  0,   0,   0,   0,   0,  62,   0,   0,  52,  53, /* 50 */
 54,  55,  56,  57,  58,  59,  60,  61,   0,   0, /* 60 */
  0,   0,   0,   0,   0,   0,   1,   2,   3,   4, /* 70 */
  5,   6,   7,   8,   9,  10,  11,  12,  13,  14, /* 80 */
 15,  16,  17,  18,  19,  20,  21,  22,  23,  24, /* 90 */
 25,   0,   0,   0,   0,  63,   0,  26,  27,  28, /* 100 */
 29,  30,  31,  32,  33,  34,  35,  36,  37,  38, /* 110 */
 39,  40,  41,  42,  43,  44,  45,  46,  47,  48, /* 120 */
 49,  50,  51,   0,   0,   0,   0,   0,   0,   0, /* 130 */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* 140 */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0, /* ... */
  0,   0,   0,   0,   0,   0,
}; /* This array has 255 elements */


unsigned char* ciron_base64url_encode(const unsigned char* data, size_t data_len,
		unsigned char *result, size_t *result_len) {

	size_t rc = 0; /* result counter */
	size_t byteNo; /* I need this after the loop */

	size_t modulusLen = data_len % 3;
	size_t pad = ((modulusLen & 1) << 1) + ((modulusLen & 2) >> 1); /* 2 gives 1 and 1 gives 2, but 0 gives 0. */

	*result_len = 4 * (data_len + pad) / 3;

	for (byteNo = 0; byteNo+3 <= data_len; byteNo += 3) {
		unsigned char BYTE0 = data[byteNo];
		unsigned char BYTE1 = data[byteNo + 1];
		unsigned char BYTE2 = data[byteNo + 2];
		result[rc++] = b64[BYTE0 >> 2];
		result[rc++] = b64[((0x3 & BYTE0) << 4) + (BYTE1 >> 4)];
		result[rc++] = b64[((0x0f & BYTE1) << 2) + (BYTE2 >> 6)];
		result[rc++] = b64[0x3f & BYTE2];
	}

	if (pad == 2) {
		result[rc++] = b64[data[byteNo] >> 2];
		result[rc++] = b64[(0x3 & data[byteNo]) << 4];
		*result_len -= 2;
		/* Removed from original code because we do not use padding.
		 res[rc++] = '=';
		 res[rc++] = '=';
		 */
	} else if (pad == 1) {
		result[rc++] = b64[data[byteNo] >> 2];
		result[rc++] = b64[((0x3 & data[byteNo]) << 4) + (data[byteNo + 1] >> 4)];
		result[rc++] = b64[(0x0f & data[byteNo + 1]) << 2];
		/* Removed from original code because we do not use padding.
		 res[rc++] = '=';
		 */
		*result_len -= 1;
	}

	/* We do not use \0 termination in our adaption
	result[rc] = 0;
	*/
	return result;
}

CironError ciron_base64url_decode(CironContext context, const unsigned char* data, size_t data_len,
		unsigned char *result, size_t *result_len) {
	size_t cb = 0;
	size_t charNo;
	size_t pad = 0;

	/* Removed from original code because we do not use padding.
	 if( safeAsciiPtr[ len-1 ]=='=' )  ++pad ;
	 if( safeAsciiPtr[ len-2 ]=='=' )  ++pad ;
	 TRACE("len:%d, mod: %d\n" _ len _ len%4);
	 */

	/* Adapted original code to handle missing padding */
	if (data_len == 1) {
                return ciron_set_error(context, __FILE__, __LINE__, NO_CRYPTO_ERROR,
                                CIRON_BASE64_ERROR, "Base64 URL-encoding cannot yield encoded length of 1");
	} else if (data_len == 2) {
		pad = 2;
		data_len = 4;
	} else if (data_len % 4 == 2) {
		pad = 2;
		data_len += 2;
	} else if (data_len % 4 == 3) {
		pad = 1;
		data_len += 1;
	} else {
		pad = 0;
	}

	*result_len = 3 * data_len / 4 - pad;
#if 0
	for (charNo = 0; charNo <= data_len - 4 - pad; charNo += 4) {
#endif
	for (charNo = 0; charNo + 4 + pad <= data_len; charNo += 4) {
		size_t A = unb64[data[charNo]];
		size_t B = unb64[data[charNo + 1]];
		size_t C = unb64[data[charNo + 2]];
		size_t D = unb64[data[charNo + 3]];

		result[cb++] = (A << 2) | (B >> 4);
		result[cb++] = (B << 4) | (C >> 2);
		result[cb++] = (C << 6) | (D);
	}
	if (pad == 1) {
		size_t A = unb64[data[charNo]];
		size_t B = unb64[data[charNo + 1]];
		size_t C = unb64[data[charNo + 2]];

		result[cb++] = (A << 2) | (B >> 4);
		result[cb++] = (B << 4) | (C >> 2);

	} else if (pad == 2) {
		size_t A = unb64[data[charNo]];
		size_t B = unb64[data[charNo + 1]];

		result[cb++] = (A << 2) | (B >> 4);

	}

	return CIRON_OK;
}
