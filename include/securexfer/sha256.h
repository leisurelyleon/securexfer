#ifndef SECUREXFER_SHA256_H
#define SECUREXFER_SHA256_H

#include <stddef.h>
#include <stdint.h>

#include "securexfer/status.h"

#define SX_SHA256_DIGEST_LEN 32 /* raw digest bytes */
#define SX_SHA256_HEX_LEN    65 /* 64 hex chars + NUL terminator */

/* Computes the SHA-256 of a buffer into a 32-byte digest. */
sx_status sx_sha256(const uint8_t *data, size_t len, uint8_t out[SX_SHA256_DIGEST_LEN]);

/* Streaming SHA-256, for hashing data larger than memory in bounded chunks. */
typedef struct sx_sha256_ctx sx_sha256_ctx;

sx_status sx_sha256_init(sx_sha256_ctx **ctx);
sx_status sx_sha256_update(sx_sha256_ctx *ctx, const uint8_t *data, size_t len);
sx_status sx_sha256_final(sx_sha256_ctx *ctx, uint8_t out[SX_SHA256_DIGEST_LEN]);

/* Formats a raw digest as lowercase hex. `out` must be SX_SHA256_HEX_LEN bytes. */
void sx_sha256_to_hex(const uint8_t digest[SX_SHA256_DIGEST_LEN], char out[SX_SHA256_HEX_LEN]);

#endif /* SECUREXFER_SHA256_H */
