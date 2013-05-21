#include "ciron.h"
#include "test.h"

int test_that_crypt_buffer_is_at_least_blocksize() {
	int n;
	Options encryption_options = DEFAULT_ENCRYPTION_OPTIONS;

	n = calculate_encryption_buffer_length(encryption_options,1);
	EXPECT_INT_EQUAL(16,n);

	n = calculate_encryption_buffer_length(encryption_options,10);
	EXPECT_INT_EQUAL(16,n);

	n = calculate_encryption_buffer_length(encryption_options,15);
	EXPECT_INT_EQUAL(16,n);


	return 1;
}

int test_that_crypt_buffer_is_block_size_boundary() {
	int n;
	Options encryption_options = DEFAULT_ENCRYPTION_OPTIONS;

	n = calculate_encryption_buffer_length(encryption_options,16);
	EXPECT_INT_EQUAL(32,n);

	n = calculate_encryption_buffer_length(encryption_options,17);
	EXPECT_INT_EQUAL(32,n);

	n = calculate_encryption_buffer_length(encryption_options,30);
	EXPECT_INT_EQUAL(32,n);

	n = calculate_encryption_buffer_length(encryption_options,200);
	EXPECT_INT_EQUAL(208,n);

	n = calculate_encryption_buffer_length(encryption_options,200665);
	EXPECT_INT_EQUAL(200672,n);

	return 1;
}

int test_that_crypt_buffer_is_block_size_for_0_or_less() {
	int n;
	Options encryption_options = DEFAULT_ENCRYPTION_OPTIONS;

	n = calculate_encryption_buffer_length(encryption_options,0);
	EXPECT_INT_EQUAL(16,n);

	n = calculate_encryption_buffer_length(encryption_options,-4);
	EXPECT_INT_EQUAL(16,n);

	return 1;
}

int test_that_seal_buffer_at_least_227() {
	int n;
	Options encryption_options = DEFAULT_ENCRYPTION_OPTIONS;
	Options integrity_options = DEFAULT_INTEGRITY_OPTIONS;

	n = calculate_seal_buffer_length(encryption_options, integrity_options,1);
	EXPECT_INT_EQUAL(227,n);

	n = calculate_seal_buffer_length(encryption_options, integrity_options,10);
	EXPECT_INT_EQUAL(227,n);

	n = calculate_seal_buffer_length(encryption_options, integrity_options,15);
	EXPECT_INT_EQUAL(227,n);

	return 1;
}

int test_seal_buffer_sizes() {
	int n;
	Options encryption_options = DEFAULT_ENCRYPTION_OPTIONS;
	Options integrity_options = DEFAULT_INTEGRITY_OPTIONS;

	n = calculate_seal_buffer_length(encryption_options, integrity_options,10);
	EXPECT_INT_EQUAL(227,n);

	n = calculate_unseal_buffer_length(encryption_options, integrity_options,227);
	EXPECT_TRUE(10 < n);

	return 1;
}

int test_that_unseal_gt_seal() {
	int ns;
	int nu;
	int N;
	Options encryption_options = DEFAULT_ENCRYPTION_OPTIONS;
	Options integrity_options = DEFAULT_INTEGRITY_OPTIONS;

	N = 1;
	ns = calculate_seal_buffer_length(encryption_options, integrity_options,N);
	nu = calculate_unseal_buffer_length(encryption_options, integrity_options,ns);
	EXPECT_TRUE(N < nu);

	N = 10;
	ns = calculate_seal_buffer_length(encryption_options, integrity_options,N);
	nu = calculate_unseal_buffer_length(encryption_options, integrity_options,ns);
	EXPECT_TRUE(N < nu);

	N = 100;
	ns = calculate_seal_buffer_length(encryption_options, integrity_options,N);
	nu = calculate_unseal_buffer_length(encryption_options, integrity_options,ns);
	EXPECT_TRUE(N < nu);

	N = 100000;
	ns = calculate_seal_buffer_length(encryption_options, integrity_options,N);
	nu = calculate_unseal_buffer_length(encryption_options, integrity_options,ns);
	EXPECT_TRUE(N < nu);

	return 1;
}

int test_that_seal_unseal_atmost_blocksiz() {
	int ns;
	int nu;
	int N;
	int BS = 16;
	Options encryption_options = DEFAULT_ENCRYPTION_OPTIONS;
	Options integrity_options = DEFAULT_INTEGRITY_OPTIONS;

	N = 1;
	ns = calculate_seal_buffer_length(encryption_options, integrity_options,N);
	nu = calculate_unseal_buffer_length(encryption_options, integrity_options,ns);
	EXPECT_TRUE((nu-N) <= BS);

	N = 10;
	ns = calculate_seal_buffer_length(encryption_options, integrity_options,N);
	nu = calculate_unseal_buffer_length(encryption_options, integrity_options,ns);
	EXPECT_TRUE((nu-N) <= BS);

	N = 100;
	ns = calculate_seal_buffer_length(encryption_options, integrity_options,N);
	nu = calculate_unseal_buffer_length(encryption_options, integrity_options,ns);
	EXPECT_TRUE((nu-N) <= BS);

	N = 100000;
	ns = calculate_seal_buffer_length(encryption_options, integrity_options,N);
	nu = calculate_unseal_buffer_length(encryption_options, integrity_options,ns);
	EXPECT_TRUE((nu-N) <= BS);

	return 1;
}


int main(int argc, char **argv) {
	RUNTEST(argv[0],test_that_crypt_buffer_is_at_least_blocksize);
	RUNTEST(argv[0],test_that_crypt_buffer_is_block_size_boundary);
	RUNTEST(argv[0],test_that_crypt_buffer_is_block_size_for_0_or_less);

	RUNTEST(argv[0],test_that_seal_buffer_at_least_227);
	RUNTEST(argv[0],test_that_unseal_gt_seal);
	RUNTEST(argv[0],test_that_seal_unseal_atmost_blocksiz);
	return 0;
}