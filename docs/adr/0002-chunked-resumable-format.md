# 2. Chunked transfer format with per-chunk hashes

- Status: Accepted
- Date: 2026-05

## Context

Transfers over unreliable or interrupted links must be resumable, and integrity
failures should be localized rather than reported as a single opaque "the file
is bad".

## Decision

Split files into fixed-size chunks and hash each chunk independently, in
addition to a whole-file hash. The manifest records every chunk's hash, offset,
and length.

## Consequences

- Resumption can re-verify only the affected chunks.
- A failing chunk is identified precisely, aiding diagnosis.
- The manifest grows linearly with file size; the default 64 KiB chunk keeps
  this proportionate.
