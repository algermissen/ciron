#ifndef TEST_H
#define TEST_H 1

#include <strings.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RUNTEST(p,f) do { int r; printf("  %s:",(p));  r = f(); if(r == 0) printf(#f " failed\n"); else printf(#f " ok\n");} while(0)

#define EXPECT_TRUE(exp) do { if(! (exp) ) { printf("Test failed in %s line %d: expected " #exp " to be true, put was false\n", __FILE__ , __LINE__ ); return 0; } } while(0)
#define EXPECT_STR_EQUAL(a,b) do { if( strncmp((a) , (b) , strlen((a))) != 0 ) { printf("Test failed in %s line %d: expected \"%s\" but got \"%s\"\n", __FILE__ , __LINE__,(a),(b) ); return 0; } } while(0)

#define EXPECT_BYTE_EQUAL(a,b,n) do { if( memcmp((a) , (b) , (n) ) != 0 ) { printf("Test failed in %s line %d: \n", __FILE__ , __LINE__ ); return 0; } } while(0)


#ifdef __cplusplus
} // extern "C"
#endif


#endif /* !defined TEST_H */
