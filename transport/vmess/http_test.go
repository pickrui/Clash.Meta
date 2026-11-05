package vmess

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/metacubex/http"
)

type httpTestOutput struct {
	net.Conn
	bytes.Buffer
}

func (c *httpTestOutput) Write(p []byte) (int, error) { return c.Buffer.Write(p) }
func (c *httpTestOutput) Read(p []byte) (int, error)  { return c.Buffer.Read(p) }

func TestHTTPConnSkipsEmptyHeaderChoices(t *testing.T) {
	wire := &httpTestOutput{}
	conn := StreamHTTPConn(wire, &HTTPConfig{Host: "example.test", Headers: map[string][]string{"Host": {}, "X-Empty": nil, "X-Test": {"present"}}})
	n, err := conn.Write([]byte("payload"))
	if err != nil || n != 7 {
		t.Fatalf("write: %d, %v", n, err)
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(wire.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	defer req.Body.Close()
	payload, err := io.ReadAll(req.Body)
	if err != nil || string(payload) != "payload" || req.Host != "example.test" || req.URL.Path != "/" || req.Header.Get("X-Test") != "present" {
		t.Fatalf("invalid request: %+v payload=%q err=%v", req, payload, err)
	}
	if _, ok := req.Header["X-Empty"]; ok {
		t.Fatal("empty header emitted")
	}
	wire.Reset()
	if n, err = conn.Write([]byte("next")); err != nil || n != 4 || wire.String() != "next" {
		t.Fatalf("next write: %d, %v, %q", n, err, wire.String())
	}
}

func TestH2ConnRejectsEmptyHosts(t *testing.T) {
	for _, method := range []string{"read", "write"} {
		t.Run(method, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("empty hosts panicked: %v", p)
				}
			}()
			conn := &h2Conn{cfg: &H2Config{}}
			var n int
			var err error
			if method == "read" {
				n, err = conn.Read(make([]byte, 1))
			} else {
				n, err = conn.Write([]byte("data"))
			}
			if n != 0 || err == nil {
				t.Fatalf("empty hosts: %d, %v", n, err)
			}
			if conn.pwriter != nil || conn.res != nil {
				t.Fatal("failed setup published a stream")
			}
		})
	}
}
