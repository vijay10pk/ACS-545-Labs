#include <stdio.h>
#include <openssl/bn.h>


#define NBITS 256


void printBN(char *msg, BIGNUM * a)
{
  char * number_str = BN_bn2hex(a);
  printf("%s %s\n", msg, number_str);
  OPENSSL_free(number_str);
}


int main ()
{
 BN_CTX *ctx = BN_CTX_new();


 BIGNUM *p, *q, *n, *phi, *e, *d, *m, *ch, *res, *s1, *m1, *s2;
 BIGNUM *new_m, *p_minus_one, *q_minus_one;
 p = BN_new(); q = BN_new(); n = BN_new(); e = BN_new(); s1 = BN_new();
 d = BN_new(); m = BN_new(); ch = BN_new(); s2 = BN_new(); m1 = BN_new();
 res = BN_new(); phi = BN_new(); new_m = BN_new();
 p_minus_one = BN_new(); q_minus_one = BN_new();


 BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
 BN_hex2bn(&e, "010001");
 BN_hex2bn(&s1, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
 BN_hex2bn(&s2, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");


 // Message: Hex to bn "Launch a missile."
 BN_hex2bn(&m, "4c61756e63682061206d697373696c65");
 printBN("Message:", m);  

 // Signature: calculate c^d mod n
 BN_mod_exp(ch, s1, e, n, ctx);
 printBN("Verify of Message with original signature:", ch);

 // Signature: calculate c^d mod n
 BN_mod_exp(ch, s2, e, n, ctx);
 printBN("Verify of Message with fake signature:", ch);

 // Clear the sensitive data from the memory            
 BN_clear_free(p); BN_clear_free(q); BN_clear_free(d);
 BN_clear_free(phi); BN_clear_free(m); BN_clear_free(new_m);
 BN_clear_free(ch); BN_clear_free(res);
 BN_clear_free(p_minus_one); BN_clear_free(q_minus_one);


 return 0;
}

