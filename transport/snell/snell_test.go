package snell

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestWriteHeaderWithReuseCommandSelection(t *testing.T) {
	tests := []struct {
		name    string
		version int
		reuse   bool
		command byte
	}{
		{name: "version2", version: Version2, reuse: false, command: CommandConnectV2},
		{name: "version3 ignores reuse", version: Version3, reuse: true, command: CommandConnect},
		{name: "version4 reuse", version: Version4, reuse: true, command: CommandConnectV2},
		{name: "version4 no reuse", version: Version4, reuse: false, command: CommandConnect},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &bufferConn{}
			if err := WriteHeaderWithReuse(conn, "example.com", 443, tt.version, tt.reuse); err != nil {
				t.Fatal(err)
			}
			got := conn.Bytes()
			if len(got) < 2 {
				t.Fatalf("header too short: %x", got)
			}
			if got[0] != Version {
				t.Fatalf("version = %d, want %d", got[0], Version)
			}
			if got[1] != tt.command {
				t.Fatalf("command = %d, want %d", got[1], tt.command)
			}
		})
	}
}

func TestParseUDPRequestAllowsEmptyDomainPayload(t *testing.T) {
	packet := append([]byte{CommondUDPForward, byte(len("example.com"))}, []byte("example.com")...)
	packet = append(packet, 0, 53)

	req, err := ParseUDPRequest(packet)
	if err != nil {
		t.Fatal(err)
	}
	if req.Host != "example.com" || req.Port != 53 || len(req.Payload) != 0 {
		t.Fatalf("unexpected request: %#v", req)
	}
}

func TestParseUDPRequestIPv4(t *testing.T) {
	packet := []byte{CommondUDPForward, 0, 4, 1, 2, 3, 4, 0, 53, 'o', 'k'}

	req, err := ParseUDPRequest(packet)
	if err != nil {
		t.Fatal(err)
	}
	if req.Ip.String() != "1.2.3.4" || req.Port != 53 || string(req.Payload) != "ok" {
		t.Fatalf("unexpected request: %#v", req)
	}
}

type bufferConn struct {
	bytes.Buffer
}

func (c *bufferConn) Close() error                     { return nil }
func (c *bufferConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *bufferConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *bufferConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
