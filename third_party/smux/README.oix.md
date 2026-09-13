# Local smux maintenance patch

Source: github.com/metacubex/smux v0.0.0-20260105030934-d0c8756d3141,
commit d0c8756d3141ce2c9aa1046df6a93985441c6033. Preserve the upstream LICENSE.
Both module roots replace this fixed version with this source directory.

The asynchronous send queue retained the caller's payload after a write returned
on deadline, session close or socket error. Reusing a TLS write buffer could then
race with smux's sendLoop. Copy the frame payload before enqueueing it, preserving
prompt cancellation and wire framing. This adds one payload allocation/copy for
each nonempty queued frame; no throughput improvement is claimed.

write_ownership_test.go deterministically checks all three cancellation paths.
The upstream README also has trailing whitespace normalized.
The only upstream test change removes the unrelated init-time pprof listener
on 0.0.0.0:6060. Protocol tests retain their upstream bodies.
