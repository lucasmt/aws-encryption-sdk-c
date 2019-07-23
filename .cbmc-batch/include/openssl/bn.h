#include <openssl/ossl_typ.h>

BIGNUM *BN_new(void);
BIGNUM *BN_dup(const BIGNUM *from);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
void BN_clear_free(BIGNUM *a);
void BN_free(BIGNUM *a);
