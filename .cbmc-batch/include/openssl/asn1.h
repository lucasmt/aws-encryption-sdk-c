#include <openssl/ossl_typ.h>

void ASN1_STRING_clear_free(ASN1_STRING *a);
BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn);
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
ASN1_INTEGER *d2i_ASN1_INTEGER(ASN1_INTEGER **a, unsigned char **ppin, long length);
int i2d_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **ppout);
