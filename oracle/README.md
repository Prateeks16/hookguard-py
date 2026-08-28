# oracle/ — test-only Go

**Nothing in this directory ships.** It is not built into any image, is listed
in `.dockerignore`, and CI asserts no Go artifact reaches a published image.

This is the Go implementation carried over from
[Prateeks16/hookguard](https://github.com/Prateeks16/hookguard). It exists for
one reason: to be the third leg of the differential harness.

The project's correctness claim is that each verifier agrees byte-for-byte with
the provider's own official library. Two of those libraries have no Python
equivalent worth diffing against — most importantly `go-github`, which ships
`ValidateSignature` where PyGithub ships nothing. Keeping the Go verifiers means
the Python verdict for GitHub is still pinned to GitHub's own library, through
this module.

It also upgrades the claim: rather than one implementation agreeing with the
vendors, two independent implementations in different languages agree with each
other *and* with the vendors, on the same committed vectors.

## How it runs

`differential_test.go` reads `../tests/vectors/signatures.json` — the same file
the Python suite reads — and asserts its verdicts against the same `expected`
column. Neither suite talks to the other; agreement is transitive through the
committed file.

The suite **fails on any vector it does not recognize** rather than skipping it,
so a vector added on the Python side cannot quietly lose Go coverage.

Populated in phase 3. See [MIGRATION.md](../MIGRATION.md) §5.
