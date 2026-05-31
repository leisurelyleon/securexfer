#include "securexfer/sha256.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

/* Modern OpenSSL 3.0 EVP interface (the legacy SHA256_* API is deprecated and
 * would trip -Werror on deprecation warnings). */

struct sx_sha256_ctx {
    EVP_MD_CTX *md;
};

sx_status sx_sha256(const uint8_t *data, size_t len, uint8_t out[SX_SHA256_DIGEST_LEN]) {
    if (data == NULL || out == NULL) {
        return SX_ERR_ARGS;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return SX_ERR_CRYPTO;
    }

    sx_status status = SX_OK;
    unsigned int out_len = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, out, &out_len) != 1) {
        status = SX_ERR_CRYPTO;
    }

    EVP_MD_CTX_free(ctx);
    return status;
}

sx_status sx_sha256_init(sx_sha256_ctx **ctx) {
    if (ctx == NULL) {
        return SX_ERR_ARGS;
    }

    sx_sha256_ctx *c = malloc(sizeof(*c));
    if (c == NULL) {
        return SX_ERR_ALLOC;
    }

    c->md = EVP_MD_CTX_new();
    if (c->md == NULL) {
        free(c);
        return SX_ERR_CRYPTO;
    }

    if (EVP_DigestInit_ex(c->md, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(c->md);
        free(c);
        return SX_ERR_CRYPTO;
    }

    *ctx = c;
    return SX_OK;
}

sx_status sx_sha256_update(sx_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    if (ctx == NULL || data == NULL) {
        return SX_ERR_ARGS;
    }
    if (EVP_DigestUpdate(ctx->md, data, len) != 1) {
        return SX_ERR_CRYPTO;
    }
    return SX_OK;
}

sx_status sx_sha256_final(sx_sha256_ctx *ctx, uint8_t out[SX_SHA256_DIGEST_LEN]) {
    if (ctx == NULL || out == NULL) {
        return SX_ERR_ARGS;
    }

    unsigned int out_len = 0;
    sx_status status = SX_OK;
    if (EVP_DigestFinal_ex(ctx->md, out, &out_len) != 1) {
        status = SX_ERR_CRYPTO;
    }

    EVP_MD_CTX_free(ctx->md);
    free(ctx);
    return status;
}

void sx_sha256_to_hex(const uint8_t digest[SX_SHA256_DIGEST_LEN], char out[SX_SHA256_HEX_LEN]) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < SX_SHA256_DIGEST_LEN; ++i) {
        out[i * 2]     = hex[(digest[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    out[SX_SHA256_DIGEST_LEN * 2] = '\0';
}
