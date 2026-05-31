This is a sample file for the securexfer demo.

Running:

    securexfer pack   data/samples/README.txt out.sxfer
    securexfer verify out.sxfer
    securexfer info   out.sxfer

will package this file into a verifiable transfer, confirm its integrity,
and print its metadata. It is intentionally small and plain so the demo runs
quickly and its hashes are easy to reason about.
