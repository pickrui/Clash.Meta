# Local sing-mux patch

Source: github.com/metacubex/sing-mux v0.3.12, copied from the Go module cache. Original Go sources, module files, README and LICENSE are retained. Both this core and the parent FlClash Go module replace this module with this directory.

Local change: `h2MuxServerSession.Close` uses `sync.Once` to close the done channel and owned connection exactly once, retaining its result for concurrent callers. The HTTP/2 ServeConn completion callback and the owning service previously both entered a check-then-close block, causing an observed `panic: close of closed channel`.

`TestH2MuxServerConcurrentClose` exercises 64 concurrent close callers and a later repeated close; the unpatched copy deterministically invokes the underlying close 64 times. Run through the root core module so its existing dependency replacements are applied:

```sh
go test -race -count=50 github.com/metacubex/sing-mux
go test -race -tags with_gvisor -count=30 -run '^TestSingMuxConcurrentDatagrams$' ./adapter/outbound
```

Updated to v0.3.12 for h2mux/yamux half-close support and initialized HTTP/2 request headers; the local concurrent-close fix and test remain applied.
