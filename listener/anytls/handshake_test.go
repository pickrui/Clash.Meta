package anytls

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
)

type limitedReadConn struct {
	net.Conn
	limit int
}

func (c *limitedReadConn) Read(p []byte) (int, error) {
	if len(p) > c.limit {
		p = p[:c.limit]
	}
	return c.Conn.Read(p)
}

func TestAnyTLSFragmentedAuthentication(t *testing.T) {
	for _, test := range []struct{ limit, pad int }{{1, 0}, {17, 1024}, {31, 0}, {34, 65535}, {65536, 72}} {
		t.Run(strconv.Itoa(test.limit)+"/padding="+strconv.Itoa(test.pad), func(t *testing.T) {
			hash := sha256.Sum256([]byte("fixture-password"))
			l := &Listener{userMap: map[[32]byte]string{hash: "fixture"}}
			padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &l.padding)
			client, peer := net.Pipe()
			defer client.Close()
			done := make(chan struct{})
			go func() { defer close(done); l.HandleConn(&limitedReadConn{Conn: peer, limit: test.limit}, nil) }()
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			data := append([]byte(nil), hash[:]...)
			data = binary.BigEndian.AppendUint16(data, uint16(test.pad))
			data = append(data, bytes.Repeat([]byte{0}, test.pad)...)
			// AnyTLS v2 heartbeat (command 8); response command 9 preserves the ID.
			data = append(data, 8, 0, 0, 0, 42, 0, 0)
			written := make(chan error, 1)
			go func() { _, err := client.Write(data); written <- err }()
			response := make([]byte, 7)
			if _, err := io.ReadFull(client, response); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(response, []byte{9, 0, 0, 0, 42, 0, 0}) {
				t.Fatal("authentication consumed the following frame")
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			client.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("handler leaked")
			}
		})
	}
}
