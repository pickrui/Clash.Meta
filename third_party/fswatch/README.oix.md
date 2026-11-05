# Local fswatch patch

Source: `github.com/metacubex/fswatch v0.1.1`, upstream commit
`6aacc3bbe574cb676e7e1348cc7722da3420bfe1`, module checksum
`h1:jqU7C/v+g0qc2RUFgmAOPoVvfl2BXXUXEumn6oQuxhU=`.
The upstream source, module files, tests, README, Makefile and license are retained.

The only runtime change closes the newly created fsnotify watcher when adding
any target fails. The caller cannot release this resource through `Close`,
because `Start` only assigns `w.watcher` after all targets have been added.
The original error and successful-start behavior are preserved.

Both `core/go.mod` and `core/Clash.Meta/go.mod` replace this module so application
builds and standalone core builds use the same fix. Run through either enclosing
module to use its selected fsnotify version:

```sh
go test -race github.com/metacubex/fswatch
```

The single added regression checks repeated failures after one target was added,
worker cleanup, and successful retry once the missing directory exists.
Retire this local replacement when a compatible upstream release includes the fix.
