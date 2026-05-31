# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffold: libsecurexfer library and securexfer CLI.

## [0.1.0] - TBD

### Added
- SHA-256 hashing via OpenSSL libcrypto with NIST known-answer tests.
- Chunked, bounded-memory file processing.
- Self-contained transfer manifest with per-chunk and whole-file hashes.
- Pack, verify, and resume operations with tamper detection.

[Unreleased]: https://github.com/leisurelyleon/securexfer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/leisurelyleon/securexfer/releases/tag/v0.1.0
