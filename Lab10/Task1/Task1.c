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

 // Set the public key exponent e, p and q value
 BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
 BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
 BN_hex2bn(&e, "0D88C3");

 BN_sub(p_minus_one, p, BN_value_one());     // Compute p-1
 BN_sub(q_minus_one, q, BN_value_one());     // Compute q-1
 BN_mul(n, p, q, ctx);                       // Compute n=pq
 BN_mul(phi, p_minus_one, q_minus_one, ctx); // Compute (*@$\phi(n)$@*)

 // Check whether e and (*@$\phi(n)$@*) are relatively prime. 
 BN_gcd(res, phi, e, ctx);
 if (!BN_is_one(res)) {
    exit(0);  // They are not relatively prime, try it again.
 }

 // Compute the private key exponent d, s.t. ed mod phi(n) = 1
 BN_mod_inverse(d, e, phi, ctx);                        
 printBN("Private key:", d);

 // Clear the sensitive data from the memory            
 BN_clear_free(p); BN_clear_free(q); BN_clear_free(d);
 BN_clear_free(phi); BN_clear_free(m); BN_clear_free(new_m);
 BN_clear_free(c); BN_clear_free(res);
 BN_clear_free(p_minus_one); BN_clear_free(q_minus_one);


 return 0;
}

