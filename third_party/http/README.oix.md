# Local HTTP/2 SETTINGS deadline fix

This is the complete `github.com/metacubex/http v0.1.8` module snapshot at
`3ffb994bb87614dd9f1fc40e036613b04b4a8ffd`, with its original sources, tests,
fixtures and BSD license retained. A trailing blank line in `.gitignore` is
trimmed. Module checksum:
`h1:d91onDan2ZXYE8W/uAy5oFmXHH2xi1L7LbGPV5EmCM0=`.
Both the enclosing mihomo module and the parent FlClash Core module replace this
dependency, so Android and desktop builds use the same fix.

The only changed upstream source is `h2_bundle.go`. Its HTTP/2 server previously
started a two-second timer after the client preface and cancelled it only after
the serve loop consumed the first frame and released the reader. Under parallel
race tests, the reader or serve loop could be delayed even though SETTINGS had
arrived. A timer callback already queued on the serve channel also closed the
connection after SETTINGS had been accepted. This caused the JLS, Snell/Restls
and deoxys inbound tests to fail with EOF or connection reset.

The server now applies the same two-second deadline to the connection read and
clears it immediately after the first frame read completes. It no longer uses a
separate SETTINGS timer message. Bytes already buffered can be processed after a
scheduling delay, while absent or incomplete network data still times out.
Failure to set or clear the deadline closes the connection. The ten-second
preface limit, frame validation, TLS authentication, stream limits and all other
protocol checks are unchanged. No test concurrency or request count is reduced.

`h2_settings_regression_test.go` uses Go 1.25+ virtual-time tests to reproduce a
reader stalled after receiving bytes and a serve loop stalled before consuming
the frame. Both cases fail against the original v0.1.8 source. It also checks
that missing SETTINGS, incomplete headers and incomplete payloads still expire
at two seconds, subsequent PING traffic works after the deadline is cleared,
and invalid first frames/settings are rejected with the original GOAWAY codes.
The build constraint applies only to these tests; production code keeps the
upstream minimum Go version.

Run from `core/Clash.Meta` so the application's dependency versions are used:

```sh
go test -race -count=1 -run '^TestHTTP2FirstSettings' github.com/metacubex/http
go test -race -count=1 -tags with_gvisor,with_mips_low_memory -p=2 -parallel=3 -timeout=300s -run '^(TestInboundShadowSocks_JLS|TestInboundSnell_Restls|TestInboundShadowSocks_Basic)$/^(Conn|deoxys-ii-256-128)$/^(aes-256-gcm|Concurrent)$/^Concurrent$' ./listener/inbound
```

Each of the three selected leaves retains 64 HTTP/2 and 64 HTTP/1.1 transfers.
The deep Go workflow runs both checks. When upgrading, compare the new module
against the checksum-verified upstream snapshot, retain its license, and reapply
or retire this fix only after the deadline and parallel regression checks pass.
