# securexfer

> A secure file transfer and integrity validator in C for constrained and air-gapped environments.

`securexfer` packages a file into a self-contained, verifiable transfer: it
splits the file into fixed-size chunks, computes a SHA-256 hash for each chunk
and for the whole file, and records them in a manifest. Verification recomputes
every hash, so any tampering or corruption is detected precisely. Because chunks
are independently hashed, an interrupted transfer can resume by re-verifying
only the chunks that are missing or changed.

## The Problem

Moving data across trust boundaries — including air-gapped and bandwidth-limited
links — requires verifiable integrity without depending on a network service.
`securexfer` provides that with no network dependency at all: the transfer
artifact is a plain on-disk format that can travel by any means, and its
integrity is self-describing.

## Architecture

```
include/securexfer/   public interface (headers)
src/                   library: sha256, chunking, manifest, transfer operations
app/                   the securexfer CLI: pack / verify / info
tests/                 unit tests, including NIST SHA-256 known-answer vectors
```

The library (`libsecurexfer.a`) is built and tested independently of the CLI.
See [`docs/architecture.md`](docs/architecture.md) and
[`docs/format.md`](docs/format.md) for the on-disk format.

## Requirements

- A C11 compiler (GCC or Clang)
- OpenSSL development headers (`libssl-dev`)

## Build & Test

```bash
make            # optimized build -> build/securexfer
make test       # build and run tests under AddressSanitizer + UBSan
```

## Run

```bash
./build/securexfer pack   data/samples/README.txt out.sxfer
./build/securexfer verify out.sxfer
./build/securexfer info   out.sxfer
```

## Security Note

`securexfer` uses OpenSSL's libcrypto for SHA-256 rather than a custom
implementation. Cryptographic primitives should come from vetted libraries; see
[`docs/adr/0001-openssl-for-crypto.md`](docs/adr/0001-openssl-for-crypto.md).

## License

MIT — see [LICENSE](LICENSE).
