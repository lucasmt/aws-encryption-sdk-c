/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <openssl/evp.h>

#include <make_common_data_structures.h>
#include <proof_helpers/nondet.h>

/* Abstraction of the EVP_PKEY struct */
struct evp_pkey_st {
    int references;
    EC_KEY *ec_key;
};

/* Helper function for CBMC proofs: initializes PKEY as nondeterministically as possible. */
void evp_pkey_nondet_init(EVP_PKEY *pkey) {
    int new_reference_count;
    __CPROVER_assume(new_reference_count > 0);
    pkey->references = new_reference_count;
}

/* Helper function for CBMC proofs: returns the reference count. */
int evp_pkey_get_reference_count(EVP_PKEY *pkey) {
    return pkey ? pkey->references : 0;
}

/* Helper function for CBMC proofs: frees the memory regardless of the reference count. */
void evp_pkey_unconditional_free(EVP_PKEY *pkey) {
    free(pkey);
}

/*
 * Description: The EVP_PKEY_new() function allocates an empty EVP_PKEY structure which is used by OpenSSL to store
 * public and private keys. The reference count is set to 1. Return values: EVP_PKEY_new() returns either the newly
 * allocated EVP_PKEY structure or NULL if an error occurred.
 */
EVP_PKEY *EVP_PKEY_new() {
    EVP_PKEY *pkey = can_fail_malloc(sizeof(EVP_PKEY));

    if (pkey) {
        pkey->references = 1;
        pkey->ec_key     = NULL;
    }

    return pkey;
}

/*
 * Description: EVP_PKEY_set1_EC_KEY() sets the key referenced by pkey to key.
 * Return values: EVP_PKEY_set1_EC_KEY() returns 1 for success or 0 for failure.
 */
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key) {
    if (pkey == NULL || key == NULL || nondet_bool()) {
        return 0;
    }

    EC_KEY_up_ref(key);
    pkey->ec_key = key;

    return 1;
}

/*
 * Description: EVP_PKEY_free() decrements the reference count of key and, if the reference count is zero, frees it up.
 * If key is NULL, nothing is done.
 */
void EVP_PKEY_free(EVP_PKEY *pkey) {
    if (pkey) {
        --pkey->references;
        if (pkey->references == 0) {
            EC_KEY_free(pkey->ec_key);  // Assuming this happens, unclear from the code and documentation
            free(pkey);
        }
    }
}

/* Abstraction of the EVP_MD_CTX struct */
struct evp_md_ctx_st {
    bool is_initialized;
    bool pkey_is_set;
    size_t data_count;
};

bool evp_md_ctx_is_valid(EVP_MD_CTX *ctx) {
    return ctx && ctx->is_initialized && ctx->data_count <= EVP_MAX_MD_SIZE;
}

bool evp_md_ctx_is_initialized(EVP_MD_CTX *ctx) {
    return ctx->is_initialized;
}

size_t evp_md_ctx_data_count(EVP_MD_CTX *ctx) {
    return ctx->data_count;
}

void evp_md_ctx_nondet_init(EVP_MD_CTX *ctx) {
    ctx->is_initialized = true;
    size_t data_count;
    __CPROVER_assume(data_count <= EVP_MAX_MD_SIZE);
    ctx->data_count = data_count;
}

/*
 * Description: Allocates and returns a digest context.
 */
EVP_MD_CTX *EVP_MD_CTX_new() {
    EVP_MD_CTX *ctx = can_fail_malloc(sizeof(EVP_MD_CTX));

    // OpenSSL implementation uses OPENSSL_zalloc, which according to the documentation returns NULL on error.
    // Therefore, we cannot guarantee that pointer is not NULL.

    if (ctx) {
        ctx->is_initialized = false;
    }

    return ctx;
}

/*
 * Description: Cleans up digest context ctx and frees up the space allocated to it.
 */
void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
    // OpenSSL implementation is a no-op if ctx is NULL
    if (ctx) {
        free(ctx);
    }
}

/*
 * Description: Sets up digest context ctx to use a digest type from ENGINE impl. type will typically be supplied by
 * a function such as EVP_sha1(). If impl is NULL then the default implementation of digest type is used. Return
 * values: Returns 1 for success and 0 for failure.
 */
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
    assert(ctx != NULL);
    assert(!ctx->is_initialized);  // can a ctx be initialized twice?
    assert(evp_md_is_valid(type));
    // impl can be NULL

    // Additional assumptions?

    ctx->is_initialized = nondet_bool();
    ctx->data_count     = 0;  // is this guaranteed?

    // Additional guarantees?

    return ctx->is_initialized;
}

/*
 * Description: Hashes cnt bytes of data at d into the digest context ctx. This function can be called several times
 * on the same ctx to hash additional data. Return values: Returns 1 for success and 0 for failure.
 */
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) {
    assert(evp_md_ctx_is_valid(ctx));
    assert(d != NULL);  // is this a hard requirement?
    assert(AWS_MEM_IS_READABLE(d, cnt));
    assert(ctx->data_count + cnt <= EVP_MAX_MD_SIZE);  // should we assume this? what happens otherwise?

    // Additional assumptions?

    if (nondet_bool()) {
        return 0;  // can failure invalidate ctx somehow?
    } else {
        ctx->data_count += cnt;
        return 1;
    }

    // Additional guarantees?
}

/*
 * Description: Retrieves the digest value from ctx and places it in md. If the s parameter is not NULL then the
 * number of bytes of data written (i.e. the length of the digest) will be written to the integer at s, at most
 * EVP_MAX_MD_SIZE bytes will be written. After calling EVP_DigestFinal_ex() no additional calls to
 * EVP_DigestUpdate() can be made, but EVP_DigestInit_ex() can be called to initialize a new digest operation.
 * Return values: Returns 1 for success and 0 for failure.
 */
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s) {
    assert(evp_md_ctx_is_valid(ctx));
    assert(md != NULL);  // is this a hard requirement?
    assert(AWS_MEM_IS_WRITABLE(md, ctx->data_count));
    // s can be NULL

    // Additional assumptions?

    if (nondet_bool()) {
        if (s) {
            *s = ctx->data_count;
        }

        ctx->is_initialized = false;

        return 1;
    } else {
        // is ctx left initialized in case of failure?
        return 0;
    }

    // Additional guarantees?
}

/*
 * Description: EVP_DigestVerifyInit() sets up verification context ctx to use digest type from ENGINE e and public key
 * pkey. ctx must be created with EVP_MD_CTX_new() before calling this function. If pctx is not NULL, the EVP_PKEY_CTX
 * of the verification operation will be written to *pctx: this can be used to set alternative verification options.
 * Note that any existing value in *pctx is overwritten. The EVP_PKEY_CTX value returned must not be freed directly by
 * the application if ctx is not assigned an EVP_PKEY_CTX value before being passed to EVP_DigestVerifyInit() (which
 * means the EVP_PKEY_CTX is created inside EVP_DigestVerifyInit() and it will be freed automatically when the
 * EVP_MD_CTX is freed). Return values: EVP_DigestVerifyInit() EVP_DigestVerifyUpdate() return 1 for success and 0 for
 * failure.
 */
int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey) {
    assert(ctx);
    assert(!ctx->is_initialized);
    assert(!pctx);  // Assuming that this function is always called in ESDK with pctx == NULL
    assert(!e);     // Assuming that this function is always called in ESDK with e == NULL
    // Which of these assumptions are actually necessary?
    assert(type);
    assert(pkey);

    if (nondet_bool()) {
        ctx->is_initialized = true;
        ctx->pkey_is_set    = true;
        return 1;
    } else {
        return 0;
    }
}

/*
 * Description: EVP_DigestVerifyFinal() verifies the data in ctx against the signature in sig of length siglen.
 * Return values: EVP_DigestVerifyFinal() and EVP_DigestVerify() return 1 for success; any other value indicates
 * failure. A return value of zero indicates that the signature did not verify successfully (that is, tbs did not match
 * the original data or the signature had an invalid form), while other values indicate a more serious error (and
 * sometimes also indicate an invalid signature form).
 */
int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen) {
    return nondet_int();
}

enum evp_aes { EVP_AES_128_GCM, EVP_AES_192_GCM, EVP_AES_256_GCM };

/* Abstraction of the EVP_CIPHER struct */
struct evp_cipher_st {
    enum evp_aes from;
};

bool evp_cipher_is_valid(EVP_CIPHER *type) {
    return type && (type->from == EVP_AES_128_GCM || type->from == EVP_AES_192_GCM || type->from == EVP_AES_256_GCM);
}

/*
 * Description: AES for 128, 192 and 256 bit keys in Galois Counter Mode (GCM). These ciphers require additional control
 * operations to function correctly, see the "AEAD Interface" in EVP_EncryptInit(3) section for details. Return values:
 * These functions return an EVP_CIPHER structure that contains the implementation of the symmetric cipher.
 */
const EVP_CIPHER *EVP_aes_128_gcm(void) {
    static const EVP_CIPHER cipher = { EVP_AES_128_GCM };
    return &cipher;
}
const EVP_CIPHER *EVP_aes_192_gcm(void) {
    static const EVP_CIPHER cipher = { EVP_AES_192_GCM };
    return &cipher;
}
const EVP_CIPHER *EVP_aes_256_gcm(void) {
    static const EVP_CIPHER cipher = { EVP_AES_256_GCM };
    return &cipher;
}

enum evp_sha { EVP_SHA256, EVP_SHA384, EVP_SHA512 };

/* Abstraction of the EVP_MD struct */
struct evp_md_st {
    enum evp_sha from;
};

bool evp_md_is_valid(EVP_MD *type) {
    return type && (type->from == EVP_SHA256 || type->from == EVP_SHA384 || type->from == EVP_SHA512);
}

/*
 * Description: The SHA-2 SHA-224, SHA-256, SHA-512/224, SHA512/256, SHA-384 and SHA-512 algorithms, which generate 224,
 * 256, 224, 256, 384 and 512 bits respectively of output from a given input. Return values: These functions return a
 * EVP_MD structure that contains the implementation of the symmetric cipher.
 */
const EVP_MD *EVP_sha256() {
    static const EVP_MD md = { EVP_SHA256 };
    return &md;
}
const EVP_MD *EVP_sha384() {
    static const EVP_MD md = { EVP_SHA384 };
    return &md;
}
const EVP_MD *EVP_sha512() {
    static const EVP_MD md = { EVP_SHA512 };
    return &md;
}
