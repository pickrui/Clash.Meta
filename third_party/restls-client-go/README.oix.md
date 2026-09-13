# Local Restls dependency

This directory is a complete source snapshot of
[`github.com/metacubex/restls-client-go v0.1.9`](https://github.com/MetaCubeX/restls-client-go/tree/v0.1.9),
the dependency selected by FlClash v0.8.97's core at
`70f0570405c3c2c47bb113b88db95006d239b346`.
Module checksum: `h1:QmLKwVFuAjB6rL9lQNKj8CuwHqGMJjV36oskeBPEtVs=`.
Upstream commit: `6566c5f8a24420fbaeb27bc74deea2597a30f4a7`.
The unmodified snapshot is local commit
`fbd77b30c4cdef9a3ccbf11a3f532c5fedfb9403` (258 files checked byte for byte).
All upstream source, tests, fixtures and license files are retained.

The local client changes are four diagnostic calls in `conn.go`:
read-side diagnostics no longer inspect `restlsToServerCounter`, and write-side
diagnostics no longer inspect `restlsToClientCounter`. Even with `debugLog = false`,
Go evaluates those arguments before calling `debugf`; concurrent reads and writes
therefore trigger the race detector. Each remaining counter read belongs to its
own direction's lock. Authentication, counters, record bytes and traffic scripts
are unchanged. The same diagnostic reads existed in v0.1.7.

The local server change in `restls_server.go` passes the connection context into
all seven fallback relay paths and closes the rate-limit wrapper on cancellation.
Closing a raw socket alone leaves both transfer goroutines waiting on long rate
reservations. The server lifecycle regression at `listener/restls/restls_test.go`
reproduces this using a one-bit-per-second fallback: shutdown must finish before
the next eight-second byte interval. The local `go.mod` minimum is Go 1.21 for
`context.AfterFunc`; the enclosing application already uses Go 1.26.

The parent `core/go.mod` and the nested core's `go.mod` both replace the module
with this directory. Both replacements are needed: dependency-module replace
statements are ignored by the main Go module. This keeps the fix in desktop,
Android and local test builds without modifying the global module cache.

Local coverage: `restls_client_regression_test.go` checks short TLS 1.2 GCM records
and authenticated records with an overstated payload or invalid command.
`transport/restls/handshake_test.go` in the enclosing module covers full-duplex
traffic, concurrent handshakes, certificate validation, all four client
fingerprints and TLS 1.2 session reuse for Chrome and Firefox. Safari/iOS do not
advertise the TLS 1.2 SessionTicket extension in these upstream fingerprints.

When updating this snapshot, compare it against the module ZIP verified by the
Go checksum database, preserve both license files, reapply or retire the
logging and fallback cancellation changes, and run the Restls CI gate and Android core checks. A compatible
upstream fix can replace this snapshot after those checks pass.

The phase-21 server reader also retains partial TLS record headers and payloads
across temporary read deadlines. HTTP Upgrade's Hijack aborts a background read;
discarding a half-read record there could break the authenticated Restls stream.
The original handshake/fallback reader is unchanged. The deadline regression
interrupts every byte boundary and verifies both the resumed and following record.

The phase-27 server flow-control fix separates application Write ordering from
record serialization. A scripted application write waiting for a client record
must release the record lock so the reader can send a control response and the
camouflage target can forward TLS records. Publish the awaiting-client state
before sending the request record, preventing fast replies from being lost.
`restls_server_flow_control_test.go` deterministically reproduces both failures
without a network or a 40-second yamux keepalive timeout. Application writes remain
ordered; control records can progress during a flow-control wait.
