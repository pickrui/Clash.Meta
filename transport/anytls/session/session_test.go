package session

import (
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
)

func TestClientSessionKeepalive(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	var factory atomic.Pointer[padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &factory)
	session := NewClientSession(client, &factory, "")
	session.keepalive = 10 * time.Millisecond
	session.Run()
	defer session.Close()
	go session.OpenStream()

	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, headerOverHeadSize)
	for {
		if _, err := io.ReadFull(server, header); err != nil {
			t.Fatal(err)
		}
		if header[0] == cmdHeartRequest {
			return
		}
		if _, err := io.CopyN(io.Discard, server, int64(binary.BigEndian.Uint16(header[5:]))); err != nil {
			t.Fatal(err)
		}
	}
}
