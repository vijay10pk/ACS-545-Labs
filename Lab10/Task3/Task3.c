#include <stdio.h>
#include <openssl/bn.h>


#define NBITS 512


void printBN(char *msg, BIGNUM * a)
{
  char * number_str = BN_bn2hex(a);
  printf("%s %s\n", msg, number_str);
  OPENSSL_free(number_str);
}


int main ()
{
 BN_CTX *ctx = BN_CTX_new();


 BIGNUM *p, *q, *n, *phi, *e, *d, *m, *c, *res;
 BIGNUM *new_m, *p_minus_one, *q_minus_one;
 p = BN_new(); q = BN_new(); n = BN_new(); e = BN_new();
 d = BN_new(); m = BN_new(); c = BN_new();
 res = BN_new(); phi = BN_new(); new_m = BN_new();
 p_minus_one = BN_new(); q_minus_one = BN_new();

//Sets the value of n,d,c
 BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
 BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
 BN_hex2bn(&c, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

 // Decryption: calculate c^d mod n
 BN_mod_exp(new_m, c, d, n, ctx);
 printBN("Decryption result:", new_m);

 // Clear the sensitive data from the memory            
 BN_clear_free(p); BN_clear_free(q); BN_clear_free(d);
 BN_clear_free(phi); BN_clear_free(m); BN_clear_free(new_m);
 BN_clear_free(c); BN_clear_free(res);
 BN_clear_free(p_minus_one); BN_clear_free(q_minus_one);


 return 0;
}

