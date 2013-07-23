#include "common.h"
#include "test.h"


int test_fixed_time_equal() {

	unsigned char single0[1] = { 0 };
	unsigned char single0_1[1] = { 0 };
	unsigned char singleFF[1] = { 255 };
	unsigned char bytes[4] = { 10, 10, 10, 10 };
	unsigned char bytes2[4] = { 255, 0, 255, 0 };
	unsigned char bytes2_1[4] = { 255, 0, 255, 0 };

	EXPECT_TRUE(ciron_fixed_time_equal(single0,single0_1,1 ));
	EXPECT_TRUE(ciron_fixed_time_equal(bytes2,bytes2_1,4 ));

	EXPECT_TRUE(!ciron_fixed_time_equal(single0,singleFF,1 ));

	EXPECT_TRUE(!ciron_fixed_time_equal(bytes,bytes2,4 ));


	return 0;
}


int main(int argc, char **argv) {

	RUNTEST(argv[0],test_fixed_time_equal);

	return 0;
}
