# Local Shadowsocks maintenance patches

Source: github.com/metacubex/sing-shadowsocks2 v0.2.7. Preserve the upstream LICENSE.
Both module roots replace this pinned dependency with this source directory.

A peer can reply before the initial socket Write returns. The upstream client
published requestSalt only after that Write and any remaining payload completed,
so concurrent reads could reject a valid reply or race with the late assignment.
Publish the immutable salt through atomic.Value before sending the request.
This preserves independent reads and writes without a duplex-blocking mutex.

shadowaead_2022/early_response_test.go holds the initial Write open until a valid
reply has been read. Both AES-128 and AES-256 cases fail with bad request salt on
v0.2.7 and pass with this patch, including under the race detector.

Backport the `noneConn.NeedHandshake` method from sing-shadowsocks2 v0.2.8
(commit 706d31e8c9a7f1d9ab94c58b326abde7026fd9cc). The `none` cipher must
report its pending destination header to early-handshake callers. The behavioral
test in cipher/method_none_test.go checks the header, payload and state transition.
Keep the local Shadowsocks 2022 salt publication fix when updating this source.
