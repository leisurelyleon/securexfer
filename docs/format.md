# Transfer Format

A `securexfer` transfer file is a UTF-8, line-oriented text document. It is
self-describing: a reader needs only this specification to parse it.

## Header

```text
SECUREXFER 1
name <basename>
size <total-bytes>
chunk_size <bytes-per-chunk>
chunks <chunk-count>
whole <sha256-hex-of-entire-file>
```

## Chunk lines

One line per chunk, in index order:

```text
chunk <index> <offset> <length> <sha256-hex-of-chunk>
```

- `index` — 0-based chunk number.
- `offset` — byte offset of the chunk in the original file.
- `length` — number of bytes in the chunk.
- the final field is the lowercase hex SHA-256 of the chunk's bytes.

## Integrity

Each chunk carries its own SHA-256, and the header carries the whole-file
SHA-256. Per-chunk hashing is what enables resumable transfers (verify only the
chunks in question) and precise tamper localization (identify which chunk
failed). A future revision may embed chunk payloads to support full content
re-hashing on verify; the current format records hashes and metadata.
