# Architecture

`securexfer` is a C11 library (`libsecurexfer.a`) plus a thin CLI, organized so
that all transfer logic is testable independently of the command-line wrapper.

## Layout

```text
include/securexfer/   public interface (headers)
src/                   library: sha256 (libcrypto), chunking, manifest, transfer
app/                   the securexfer CLI: pack / verify / info
tests/                 unit tests, including NIST SHA-256 known-answer vectors
```

## Components

- **sha256** — SHA-256 over OpenSSL's EVP interface, with a streaming context
  for hashing data larger than memory in bounded pieces.
- **chunk** — splits a file into fixed-size chunks and hashes each one.
- **manifest** — a self-describing, line-oriented record of file metadata,
  per-chunk hashes, and the whole-file hash.
- **transfer** — packs a file into a transfer artifact, and verifies integrity.

## Memory discipline

The library reads files in bounded chunks (default 64 KiB), so peak memory is
independent of file size. Every allocation is checked, and every path —
including error paths — releases what it acquired. Tests are run under
AddressSanitizer and UndefinedBehaviorSanitizer to enforce this.

## Status codes

Functions return `sx_status` rather than leaking `errno`, giving callers a
stable, documented set of outcomes including a distinct integrity-failure code.
