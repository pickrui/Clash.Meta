# Local mips TUN memory profile

Source: github.com/metacubex/sing-tun v0.4.24, copied from the Go module cache with its license, sources and tests retained. Both the mihomo module and FlClash core replace this dependency with this directory.

Under `with_mips_low_memory`, `Mipstack.config` explicitly sets TCP send and receive buffers to 32 KiB initially, each allowed to grow to 128 KiB. This is the socket profile used in the Hako low-memory comparison, alongside the mipstack storage patch documented in `../mipstack/README.oix.md`. Keepalive, routing, MTU and UDP configuration are unchanged. Builds without the dedicated tag use the original mipstack socket defaults.

Smaller TCP maxima can limit throughput on high-latency links. Validate memory and transfer behavior together; these bounds are not a process memory cap. The low-memory stream test forwards IPv4 and IPv6 through the actual mips TUN adapter, transfers more than the buffer maximum, and reuses the connection afterward.

Run tests from `core/` with the application replacements active:

```sh
go test -race -tags with_gvisor,with_mips_low_memory github.com/metacubex/sing-tun
go test -race -tags with_gvisor github.com/metacubex/sing-tun
```
