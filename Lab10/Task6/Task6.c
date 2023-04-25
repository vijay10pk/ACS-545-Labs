#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>

#define NBITS 256
#define SHA_LENGTH 64


void printBN(char *msg, BIGNUM * a)
{
  char * number_str = BN_bn2hex(a);
  printf("%s %s\n", msg, number_str);
  OPENSSL_free(number_str);
}


int main ()
{
 BN_CTX *ctx = BN_CTX_new();


 BIGNUM *p, *q, *n, *phi, *e, *d, *m, *ch, *res, *s;
 BIGNUM *new_m, *p_minus_one, *q_minus_one;
 p = BN_new(); q = BN_new(); n = BN_new(); e = BN_new(); s = BN_new();
 d = BN_new(); m = BN_new(); ch = BN_new();
 res = BN_new(); phi = BN_new(); new_m = BN_new();
 p_minus_one = BN_new(); q_minus_one = BN_new();


 BN_hex2bn(&n, "D753A40451F899A616484B6727AA9349D039ED0CB0B00087F1672886858C8E63DABCB14038E2D3F5ECA50518B83D3EC5991732EC188CFAF10CA6642185CB071034B052882B1F689BD2B18F12B0B3D2E7881F1FEF387754535F80793F2E1AAAA81E4B2B0DABB763B935B77D14BC594BDF514AD2A1E20CE29082876AAEEAD764D69855E8FDAF1A506C54BC11F2FD4AF29DBB7F0EF4D5BE8E16891255D8C07134EEF6DC2DECC48725868DD821E4B04D0C89DC392617DDF6D79485D80421709D6F6FFF5CBA19E145CB5657287E1C0D4157AAB7B827BBB1E4FA2AEF2123751AAD2D9B86358C9C77B573ADD8942DE4F30C9DEEC14E627E17C0719E2CDEF1F910281933");
 BN_hex2bn(&e, "10001");
 BN_hex2bn(&s, "0b4766bb8e1a5795099466be016e95d0bfae9abaa3e3c391285c9571125bd9e07ada509cb862ada122f4b82c95c8dfb0ce8501443b8cbeeedccddd2444dfbefd7a1ad1cc8776083d366dcf445e090ff71495b2701ded29048e3ed05a8034c06e66b98003aed25a8feb6ca6092710b01c414cdea05c32e18dfd5e29bdd7518d5e1c63fc0734f8247605ef681e90e430c17e844ad255fd5c956e325f89e3185a780f3110417ece2b92708d6ab67c3e5e6b9bb103f376c3ae33f5553ef2de8dde3fbee4cf26ebea806797b3a2a2bedf1ee8a457e0529d17090092a7ab74318f0cdb681f87c44f0a0bf6eb1c7899f45de5f66253acd504b09270700413b7bb51f6cb");



 BN_hex2bn(&m, "710e017b0e642997a3115fb9c4f0a1f8e5378a8578e6e05a06b43b4d21b7fc09");
 printBN("Message:", m);  

 // Signature: calculate c^d mod n
 BN_mod_exp(ch, s, e, n, ctx);

 
 char *result = BN_bn2hex(ch);
 char substr[65];
 strncpy(substr, result + strlen(result) - SHA_LENGTH, SHA_LENGTH);
 BN_hex2bn(&ch, substr);
   
 printBN("Verify of Message with original signature:", ch);
 
 // Clear the sensitive data from the memory            
 BN_clear_free(p); BN_clear_free(q); BN_clear_free(d);
 BN_clear_free(phi); BN_clear_free(m); BN_clear_free(new_m);
 BN_clear_free(ch); BN_clear_free(res);
 BN_clear_free(p_minus_one); BN_clear_free(q_minus_one);


 return 0;
}

