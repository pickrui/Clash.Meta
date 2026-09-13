# Legacy cache fixture

`bbolt-1.4-cache.db.gz` was written by the actual CacheFile methods at core
commit `c3cca07ec0430d8a05fba29f1381b0174f93f059`, with
`github.com/metacubex/bbolt v0.0.0-20250725135710-010dbbbb7a5b` selected.
It uses a 4096-byte database page size and contains only synthetic values:
proxy selection, IPv4/IPv6 FakeIP mappings, ETag/hash/time, subscription
metadata and binary script storage. No production cache was read.

To regenerate, use a separate checkout of that core commit and run:

```sh
go run /absolute/path/to/generate_legacy.go /tmp/bbolt-1.4-cache.db.gz
```

The generator refuses a different selected bbolt version. Its build-ignore
constraint excludes it from normal tests. Storage timestamps and physical
page layout may differ when regenerated; assertions concern logical values.

Compressed SHA-256: `524f97f4f9699a55c268b7ed65ce568d91db881efece140558c8faa3bf7ce8a0`

Uncompressed SHA-256: `6155200f22533d5c5c368a81e05c75b1a94e3dce24434563a5e23079db4b0ecf`
