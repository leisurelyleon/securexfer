# 3. Bounded-memory streaming

- Status: Accepted
- Date: 2026-05

## Context

The tool must handle files larger than available memory, including in
constrained environments, without exhausting resources.

## Decision

Process files in fixed-size chunks using a streaming hash context. Peak memory
is bounded by the chunk size (default 64 KiB) regardless of file size.

## Consequences

- Arbitrarily large files can be processed in constant memory.
- Hashing is incremental; no full-file buffer is ever allocated.
- The chunk size is a tunable trade-off between memory and manifest size.
