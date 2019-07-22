#include <aws/cryptosdk/cipher.h>
#include <make_common_data_structures.h>
#include <proof_allocators.h>
#include <proof_helpers/proof_allocators.h>
#include <ec_utils.h>
#include <evp_utils.h>

#include <cipher_openssl.h>

void harness() {
    /* arguments */
    enum aws_cryptosdk_alg_id alg_id;

    /* operation under verification */
    struct aws_cryptosdk_alg_properties* props = aws_cryptosdk_alg_props(alg_id);

    /* assertions */
    if (props) {
      assert(props->impl->md_ctor == NULL || props->impl->md_ctor == EVP_sha256 || props->impl->md_ctor == EVP_sha384);
      assert(props->impl->cipher_ctor == NULL || props->impl->cipher_ctor == EVP_aes_128_gcm || props->impl->cipher_ctor == EVP_aes_192_gcm || props->impl->cipher_ctor == EVP_aes_256_gcm);
    }
}
