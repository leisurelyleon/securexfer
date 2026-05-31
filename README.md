# securexfer
A secure file transfer and integrity validator in C for constrained and air-gapped environments. Splits files into verifiable chunks, computes SHA-256 hashes per chunk and whole-file, supports resumable transfers, and detects tampering — built with zero network dependencies and a self-contained on-disk transfer format.
