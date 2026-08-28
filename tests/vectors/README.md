# Signature vectors

`signatures.json` is the interchange for the three-way differential harness
(MIGRATION.md §05). It is **committed**, not generated at test time: both the
Python suite and the Go suite under `oracle/` read this exact file and assert
against the same `expected` verdict, which is what makes agreement between the
two implementations provable rather than coordinated at runtime.

Body bytes are base64-encoded so nothing normalizes them in transit.

Authored in phase 3.
