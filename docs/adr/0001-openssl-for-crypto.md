# 1. OpenSSL libcrypto for SHA-256

- Status: Accepted
- Date: 2026-05

## Context

The transfer integrity guarantee rests entirely on the hash function. A custom
SHA-256 implementation, however careful, is a liability: cryptographic code is
notoriously easy to get subtly wrong, and a flawed hash silently undermines the
whole system.

## Decision

Use OpenSSL's libcrypto (the EVP interface) for SHA-256 rather than a custom
implementation. libcrypto is widely deployed, audited, and maintained.

## Consequences

- Integrity rests on a vetted implementation.
- The project depends on OpenSSL development headers at build time.
- The EVP interface (not the deprecated SHA256_* functions) is used, keeping the
  build clean under modern OpenSSL.
