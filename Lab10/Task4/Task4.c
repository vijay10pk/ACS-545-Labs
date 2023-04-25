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


 BIGNUM *p, *q, *n, *phi, *e, *d, *m, *c, *res, *s, *m1;
 BIGNUM *new_m, *p_minus_one, *q_minus_one;
 p = BN_new(); q = BN_new(); n = BN_new(); e = BN_new();
 d = BN_new(); m = BN_new(); c = BN_new(); s = BN_new(); m1 = BN_new();
 res = BN_new(); phi = BN_new(); new_m = BN_new();
 p_minus_one = BN_new(); q_minus_one = BN_new();


 BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
 BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
 BN_hex2bn(&e, "010001");

 // Message: Hex to bn "I owe you $2000"
 BN_hex2bn(&m, "49206f776520796f75202432303030");   


 // Signature: calculate c^d mod n
 BN_mod_exp(s, m, d, n, ctx);
 printBN("Signature of Message 1:", s);

 // Message: Hex to bn "I owe you $3000"
 BN_hex2bn(&m1, "49206f776520796f75202433303030");   

 // Signature: calculate c^d mod n
 BN_mod_exp(s, m1, d, n, ctx);
 printBN("Signature of Message 2:", s);

 // Clear the sensitive data from the memory            
 BN_clear_free(p); BN_clear_free(q); BN_clear_free(d);
 BN_clear_free(phi); BN_clear_free(m); BN_clear_free(new_m);
 BN_clear_free(c); BN_clear_free(res);
 BN_clear_free(p_minus_one); BN_clear_free(q_minus_one);


 return 0;
}

