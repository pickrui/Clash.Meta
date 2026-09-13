package vmess

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"testing"

	"github.com/metacubex/http"
)

type upgradeTestConn struct {
	net.Conn
	reader io.Reader
}

func (c *upgradeTestConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type upgradeTestWriter struct {
	header http.Header
	conn   net.Conn
	reader *bufio.Reader
	status int
}

func (w *upgradeTestWriter) Header() http.Header         { return w.header }
func (w *upgradeTestWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *upgradeTestWriter) WriteHeader(status int)      { w.status = status }
func (w *upgradeTestWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(w.reader, bufio.NewWriter(io.Discard)), nil
}

func TestHTTPUpgradeEarlyDataPrecedesBufferedPayload(t *testing.T) {
	for _, prefetch := range []bool{false, true} {
		for _, early := range [][]byte{[]byte("early-"), bytes.Repeat([]byte{'e'}, 5000)} {
			later := []byte("later")
			raw := &upgradeTestConn{reader: bytes.NewReader(later)}
			reader := bufio.NewReader(raw)
			if prefetch {
				if _, err := reader.Peek(len(later)); err != nil {
					t.Fatal(err)
				}
			}
			writer := &upgradeTestWriter{header: make(http.Header), conn: raw, reader: reader}
			request := &http.Request{Header: http.Header{"Upgrade": {"websocket"}, "Sec-Websocket-Protocol": {base64.RawURLEncoding.EncodeToString(early)}}}
			conn, err := StreamUpgradedWebsocketConn(writer, request)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(conn)
			if err != nil {
				t.Fatal(err)
			}
			want := append(bytes.Clone(early), later...)
			if !bytes.Equal(got, want) {
				t.Errorf("prefetch=%t early=%d: data order changed", prefetch, len(early))
			}
			if writer.status != http.StatusSwitchingProtocols {
				t.Fatal("missing upgrade response")
			}
		}
	}
}
