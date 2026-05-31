#!/usr/bin/env bash
# Pack a sample file, verify it, show info, then tamper and re-verify to
# demonstrate integrity detection.
set -euo pipefail

make clean
make
mkdir -p out

echo "== Packing sample =="
./build/securexfer pack data/samples/README.txt out/sample.sxfer

echo
echo "== Info =="
./build/securexfer info out/sample.sxfer

echo
echo "== Verifying (expect: intact) =="
./build/securexfer verify out/sample.sxfer

echo
echo "== Tampering with the transfer and re-verifying (expect: failure) =="
# Corrupt a chunk's index so it no longer matches its position.
sed -i 's/^chunk 0 /chunk 9 /' out/sample.sxfer || true
if ./build/securexfer verify out/sample.sxfer; then
    echo "UNEXPECTED: tampered file passed verification"
else
    echo "Tampering correctly detected."
fi
