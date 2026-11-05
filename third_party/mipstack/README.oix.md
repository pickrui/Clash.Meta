# Local mipstack low-memory policy

Source: github.com/metacubex/mipstack v0.0.0-20260919101445-802d64336f8c, copied from the Go module cache with its MPL-2.0 license, sources and tests retained. Both the mihomo module and FlClash core replace this dependency with this directory.

Backport: https://github.com/MetaCubeX/mipstack/pull/3 at commit `456a89053ab2a5b08cc9e90be294871f2505027a`. The source baseline is newer than the PR; the benchmark helper preserves its newer MTU argument. Production changes otherwise match the upstream storage policy.

`with_mips_low_memory` is an additional selector for the same policy as upstream `with_low_memory`. FlClash uses the dedicated tag so other mihomo stacks and shared buffer pools keep their existing behavior. Builds without either tag retain the original policy. Socket window defaults remain unchanged here; sing-tun supplies the smaller TUN profile explicitly.

The first send allocation is 1 KiB, an acknowledged reusable send chunk is at most 16 KiB, and drained receive metadata retains at most 32 slots. The small-spare fit check avoids a 16 KiB tail allocation. Live, unread and unacknowledged data remain intact. No forced GC or runtime memory polling is added.

From `core/`, run both variants using the application dependency graph:

```sh
go test -race -tags with_gvisor,with_mips_low_memory github.com/metacubex/mipstack github.com/metacubex/sing-tun
go test -race -tags with_gvisor github.com/metacubex/mipstack github.com/metacubex/sing-tun
go test -v -tags with_mips_low_memory -run TestTCPMemoryProfileBaseline github.com/metacubex/mipstack
go test -run '^$' -bench BenchmarkTCPMemoryProfileStream -benchtime=1s github.com/metacubex/mipstack
go test -tags with_mips_low_memory -run '^$' -bench BenchmarkTCPMemoryProfileStream -benchtime=1s github.com/metacubex/mipstack
```

The deterministic profile counts retained backing, not Android RSS. Upstream's iPad measurements in LOW_MEMORY.md describe its own workload. The separate upstream gVisor interoperability race suite had unresolved timeouts; the application TUN tests here are a different suite.
