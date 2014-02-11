#include "ciron.h"
#include "test.h"

struct CironContext ctx;

const size_t password_id_len = 6;


int test_that_crypt_buffer_is_at_least_blocksize() {
	size_t n;
    ciron_context_init(&ctx,CIRON_DEFAULT_ENCRYPTION_OPTIONS,CIRON_DEFAULT_INTEGRITY_OPTIONS);

	ciron_calculate_encryption_buffer_length(&ctx,(size_t)1,&n);

	EXPECT_SIZE_T_EQUAL((size_t)16,n);

	ciron_calculate_encryption_buffer_length(&ctx,10,&n);
	EXPECT_SIZE_T_EQUAL((size_t)16,n);

	ciron_calculate_encryption_buffer_length(&ctx,15,&n);
	EXPECT_SIZE_T_EQUAL((size_t)16,n);


	return 0;
}

int test_that_crypt_buffer_is_block_size_boundary() {
	size_t n;
	ciron_context_init(&ctx,CIRON_DEFAULT_ENCRYPTION_OPTIONS,CIRON_DEFAULT_INTEGRITY_OPTIONS);

	ciron_calculate_encryption_buffer_length(&ctx,16,&n);
	EXPECT_SIZE_T_EQUAL((size_t)32,n);

	ciron_calculate_encryption_buffer_length(&ctx,17,&n);
	EXPECT_SIZE_T_EQUAL((size_t)32,n);

	ciron_calculate_encryption_buffer_length(&ctx,30,&n);
	EXPECT_SIZE_T_EQUAL((size_t)32,n);

	ciron_calculate_encryption_buffer_length(&ctx,200,&n);
	EXPECT_SIZE_T_EQUAL((size_t)208,n);

	ciron_calculate_encryption_buffer_length(&ctx,200665,&n);
	EXPECT_SIZE_T_EQUAL((size_t)200672,n);

	return 0;
}

int test_that_crypt_buffer_is_block_size_for_0() {
	size_t n;
	ciron_context_init(&ctx,CIRON_DEFAULT_ENCRYPTION_OPTIONS,CIRON_DEFAULT_INTEGRITY_OPTIONS);


	ciron_calculate_encryption_buffer_length(&ctx,0,&n);
	EXPECT_SIZE_T_EQUAL((size_t)16,n);

	return 0;
}

int test_that_seal_buffer_at_least_227() {
	size_t n;
	ciron_context_init(&ctx,CIRON_DEFAULT_ENCRYPTION_OPTIONS,CIRON_DEFAULT_INTEGRITY_OPTIONS);

	ciron_calculate_seal_buffer_length(&ctx,1,password_id_len,&n);
	EXPECT_SIZE_T_EQUAL((size_t)227+password_id_len,n);

	ciron_calculate_seal_buffer_length(&ctx,10,password_id_len,&n);
	EXPECT_SIZE_T_EQUAL((size_t)227+password_id_len,n);

	ciron_calculate_seal_buffer_length(&ctx,15,password_id_len,&n);
	EXPECT_SIZE_T_EQUAL((size_t)227+password_id_len,n);

	return 0;
}

int test_seal_buffer_sizes() {
	size_t n;
	ciron_context_init(&ctx,CIRON_DEFAULT_ENCRYPTION_OPTIONS,CIRON_DEFAULT_INTEGRITY_OPTIONS);

	ciron_calculate_seal_buffer_length(&ctx,10,password_id_len,&n);
	EXPECT_SIZE_T_EQUAL((size_t)227+password_id_len,n);

	ciron_calculate_unseal_buffer_length(&ctx,227+password_id_len,&n);
	EXPECT_TRUE(10 < n);

	return 0;
}

int test_that_unseal_gt_seal() {
	size_t ns;
	size_t nu;
	size_t N;
	ciron_context_init(&ctx,CIRON_DEFAULT_ENCRYPTION_OPTIONS,CIRON_DEFAULT_INTEGRITY_OPTIONS);

	N = 1;
	ciron_calculate_seal_buffer_length(&ctx,N,password_id_len,&ns);
	ciron_calculate_unseal_buffer_length(&ctx,ns,&nu);
	EXPECT_TRUE(N < nu);

	N = 10;
	ciron_calculate_seal_buffer_length(&ctx,N,password_id_len,&ns);
	ciron_calculate_unseal_buffer_length(&ctx,ns,&nu);
	EXPECT_TRUE(N < nu);

	N = 100;
	ciron_calculate_seal_buffer_length(&ctx,N,password_id_len,&ns);
	ciron_calculate_unseal_buffer_length(&ctx,ns,&nu);
	EXPECT_TRUE(N < nu);

	N = 100000;
	ciron_calculate_seal_buffer_length(&ctx,N,password_id_len,&ns);
	ciron_calculate_unseal_buffer_length(&ctx,ns,&nu);
	EXPECT_TRUE(N < nu);

	return 0;
}

int test_that_seal_unseal_atmost_blocksiz() {
	size_t ns;
	size_t nu;
	size_t N;
	size_t BS = 16;
	ciron_context_init(&ctx,CIRON_DEFAULT_ENCRYPTION_OPTIONS,CIRON_DEFAULT_INTEGRITY_OPTIONS);

	N = 1;
	ciron_calculate_seal_buffer_length(&ctx,N,password_id_len,&ns);
	ciron_calculate_unseal_buffer_length(&ctx,ns,&nu);
	EXPECT_TRUE((nu-N) <= BS+password_id_len);

	N = 10;
	ciron_calculate_seal_buffer_length(&ctx,N,password_id_len,&ns);
	ciron_calculate_unseal_buffer_length(&ctx,ns,&nu);
	EXPECT_TRUE((nu-N) <= BS);

	N = 100;
	ciron_calculate_seal_buffer_length(&ctx,N,password_id_len,&ns);
	ciron_calculate_unseal_buffer_length(&ctx,ns,&nu);
	EXPECT_TRUE((nu-N) <= BS+password_id_len);

	N = 100000;
	ciron_calculate_seal_buffer_length(&ctx,N,password_id_len,&ns);
	ciron_calculate_unseal_buffer_length(&ctx,ns,&nu);
	EXPECT_TRUE((nu-N) <= BS + password_id_len);

	return 0;
}


int main(int argc, char **argv) {
	RUNTEST(argv[0],test_that_crypt_buffer_is_at_least_blocksize);
	RUNTEST(argv[0],test_that_crypt_buffer_is_block_size_boundary);
	RUNTEST(argv[0],test_that_crypt_buffer_is_block_size_for_0);

	RUNTEST(argv[0],test_that_seal_buffer_at_least_227);
	RUNTEST(argv[0],test_that_unseal_gt_seal);
	RUNTEST(argv[0],test_that_seal_unseal_atmost_blocksiz);
	return 0;
}
