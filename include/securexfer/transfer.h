#ifndef SECUREXFER_TRANSFER_H
#define SECUREXFER_TRANSFER_H

#include <stdint.h>

#include "securexfer/manifest.h"
#include "securexfer/status.h"

/* Packs `source_path` into a self-contained transfer file at `dest_path`,
 * computing per-chunk and whole-file hashes. */
sx_status sx_pack(const char *source_path, const char *dest_path, uint32_t chunk_size);

/* Verifies a transfer file's integrity by recomputing every hash. Returns
 * SX_OK when intact, SX_ERR_INTEGRITY on any mismatch. `bad_chunk_out`, if
 * non-NULL, receives the index of the first failing chunk on integrity error. */
sx_status sx_verify(const char *transfer_path, uint64_t *bad_chunk_out);

/* Reads and returns the manifest from a transfer file (for `info`). */
sx_status sx_read_manifest(const char *transfer_path, sx_manifest **out);

#endif /* SECUREXFER_TRANSFER_H */
