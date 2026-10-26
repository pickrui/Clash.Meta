# Local Windows TCP Fast Open layout fix

Source: `github.com/metacubex/tfo-go v0.0.0-20260623020846-376a77860b8c`,
module checksum `h1:+2C1UshSLzaogLY/IDz1XhOLxjhs3rkhVHB4eCN9Zto=`.
The original module sources, tests, fixtures and MIT license are retained.
The Windows poll.FD mirrors come from Go's `src/internal/poll/fd_windows.go`;
its BSD license is retained as `LICENSE_GO`.
Both `core/go.mod` and `core/Clash.Meta/go.mod` replace this dependency.

The checked Go 1.26.9, Go 1.26.10 and Go 1.27.3 sources include
`KeepFileCompletionModes` in the Windows `internal/poll.FD`. The upstream TFO mirror omitted it, shifting the subsequent
flags. After TFO's `associated = true`, converting its socket to `net.TCPConn`
made the standard library read `isBlocking = true` and `associated = false`.
An overlapped read or write could therefore return before its completion.
The field is absent in the locally checked Go 1.26.8 and Go 1.27.1 sources.

The Go 1.26 and 1.27 mirrors now include the field. Before constructing any
Windows socket through the private mirror, a cached reflection check compares
`net.TCPConn`, `netFD` and every nested field's type, size, alignment and offset.
Compatible toolchains retain TFO. An older or unknown incompatible layout uses
standard TCP with the same local address, ControlContext, deadlines and early
data. This fallback runs before socket creation, never retries partially sent
data, and uses the existing context-aware write and failure cleanup path.
Short early-data writes now return `io.ErrShortWrite` instead of succeeding.
Windows listeners already use `net.ListenConfig` and do not use private FDs.

`TestWindowsPollFDLayout` in the existing test file checks the copied fields
against the selected toolchain's Windows source on any host. The Windows-only
regression checks the actual reflection guard and reuses the existing early-data
roundtrip helper with a forced incompatible layout, a local bind and ControlContext.
It also checks cancellation before the fallback dial. Existing TFO roundtrip,
address, Control and deadline tests are retained.

Run from either enclosing module to use the application's dependency versions:

```sh
go test -race -count=1 github.com/metacubex/tfo-go
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/tfo-windows.test.exe github.com/metacubex/tfo-go
```

Cross-compilation and the portable layout check do not execute Windows socket
I/O. Run the same suite on Windows with the pinned Go 1.27.3 before claiming that
runtime validation. Retire this replacement when upstream provides a compatible
fix, retaining the layout guard against subsequent Go patch changes.
