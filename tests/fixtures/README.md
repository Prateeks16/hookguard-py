# Fixtures

## `go-console.db`

A Console database written by the **Go** implementation: `oracle/fixturegen`
links the Go console's own `store` and `auth` packages and populates every
table. Nothing here was produced by the Python port, which is the point --
`tests/console/test_store_go_fixture.py` asserts interoperability, and a
fixture we generated ourselves would only prove self-consistency.

`go-console.json` is the manifest: the ids, the session token whose SHA-256 is
in the database, and the plaintext password whose Argon2 hash is stored. Those
values are fixtures, not secrets; the database contains no real credentials.

The Argon2 hash is also the phase 5 check. It carries the parameters the schema
documents (`$argon2id$v=19$m=65536,t=3,p=2$`), and `argon2-cffi` must verify it
unchanged -- which is what makes an existing console database migrate to the
Python build with no user action.

### Regenerating

Only needed if the Go schema or `auth` package changes. Requires the Go
repository checked out beside this one:

```sh
cd oracle/fixturegen
go run . ../../tests/fixtures/go-console.db ../../tests/fixtures/go-console.json
```

The tests copy the database to a temp path before opening it, so SQLite's WAL
siblings never land next to the committed file.
