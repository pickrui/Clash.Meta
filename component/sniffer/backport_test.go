package sniffer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	S "github.com/metacubex/mihomo/constant/sniffer"
	"github.com/metacubex/quic-go/quicvarint"
	"github.com/metacubex/tls"
)

// Model partial TCP reads faithfully: a short destination preserves the rest
// of the segment. No network or real clock timeout is needed.
type relayTestConn struct {
	net.Conn
	chunks   [][]byte
	firstErr error
	writes   bytes.Buffer
	closed   bool
	deadline time.Time
	reads    int
}

func (c *relayTestConn) Read(b []byte) (int, error) {
	c.reads++
	if c.firstErr != nil {
		err := c.firstErr
		c.firstErr = nil
		return 0, err
	}
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(b, c.chunks[0])
	c.chunks[0] = c.chunks[0][n:]
	if len(c.chunks[0]) == 0 {
		c.chunks = c.chunks[1:]
	}
	return n, nil
}
func (c *relayTestConn) Write(b []byte) (int, error)       { return c.writes.Write(b) }
func (c *relayTestConn) Close() error                      { c.closed = true; return nil }
func (c *relayTestConn) SetReadDeadline(d time.Time) error { c.deadline = d; return nil }
func (c *relayTestConn) SetWriteDeadline(time.Time) error  { return nil }
func (c *relayTestConn) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (c *relayTestConn) RemoteAddr() net.Addr              { return &net.TCPAddr{} }

func port12ClientHello(t *testing.T) []byte {
	t.Helper()
	raw := &relayTestConn{}
	client := tls.Client(raw, &tls.Config{ServerName: "sniff.test"})
	// Capture an actual ClientHello from the TLS library, then let EOF end the
	// handshake. The following bytes are generated locally, not a saved capture.
	if err := client.Handshake(); err == nil {
		t.Fatal("unexpected handshake without server")
	}
	wire := raw.writes.Bytes()
	if len(wire) < 5 || wire[0] != 0x16 {
		t.Fatal("TLS client did not send a handshake record")
	}
	n := int(binary.BigEndian.Uint16(wire[3:5]))
	if n > len(wire)-5 {
		t.Fatal("incomplete TLS client record")
	}
	return bytes.Clone(wire[5 : 5+n])
}
func port12TLSRecords(hello []byte, cuts ...int) []byte {
	var wire []byte
	start := 0
	for _, end := range append(cuts, len(hello)) {
		wire = append(wire, 0x16, 0x03, 0x03, byte((end-start)>>8), byte(end-start))
		wire = append(wire, hello[start:end]...)
		start = end
	}
	return wire
}
func port12Dispatcher(t *testing.T, protocols map[S.Type]SnifferConfig) *Dispatcher {
	t.Helper()
	sd, err := NewDispatcher(&Config{Enable: true, ParsePureIp: true, Sniffers: protocols})
	if err != nil {
		t.Fatal(err)
	}
	return sd
}
func port12Metadata(port uint16) *C.Metadata {
	return &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: port}
}

func TestSniffFragmentedTLSKeepsRelayBytes(t *testing.T) {
	hello := port12ClientHello(t)
	wire := port12TLSRecords(hello, 2, 43)
	original := bytes.Clone(wire)
	raw := &relayTestConn{chunks: [][]byte{wire[:3], wire[3:8], wire[8:21], wire[21:]}}
	conn := N.NewBufferedConn(raw)
	sd := port12Dispatcher(t, map[S.Type]SnifferConfig{S.TLS: {OverrideDest: true}})
	metadata := port12Metadata(443)
	if !sd.TCPSniff(conn, metadata) || metadata.Host != "sniff.test" {
		t.Errorf("fragmented ClientHello: host=%q sniff=%q", metadata.Host, metadata.SniffHost)
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, original) {
		t.Fatal("sniffing changed or consumed TLS relay bytes")
	}
	if raw.closed || !raw.deadline.IsZero() {
		t.Fatal("sniffing closed the relay or retained a read deadline")
	}
}

func TestSniffInitialTimeoutKeepsRelayAlive(t *testing.T) {
	wire := []byte("server-first protocol response")
	raw := &relayTestConn{firstErr: &net.OpError{Op: "read", Net: "tcp", Err: timeoutTestError{}}, chunks: [][]byte{wire}}
	conn := N.NewBufferedConn(raw)
	sd := port12Dispatcher(t, map[S.Type]SnifferConfig{S.TLS: {}})
	metadata := port12Metadata(443)
	if sd.TCPSniff(conn, metadata) {
		t.Fatal("timeout produced a sniffed domain")
	}
	if raw.closed {
		t.Error("initial sniff timeout closed caller's connection")
	}
	failures, _ := sd.skipList.Get(metadata.AddrPort())
	if failures != 1 {
		t.Errorf("failure counted %d times, want once", failures)
	}
	data, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(data, wire) {
		t.Fatalf("relay after timeout: data=%q err=%v", data, err)
	}
	if !raw.deadline.IsZero() {
		t.Fatal("deadline was not cleared")
	}
}

type timeoutTestError struct{}

func (timeoutTestError) Error() string   { return "test read timeout" }
func (timeoutTestError) Timeout() bool   { return true }
func (timeoutTestError) Temporary() bool { return true }

func TestSniffHTTPHostBeforeTrailingHeaders(t *testing.T) {
	h, err := NewHTTPSniffer(SnifferConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range []string{
		"GET / HTTP/1.1\r\nHost: SNIFF.TEST.:443\r\nX-Pending: ",
		"GET http://SNIFF.TEST.:443/path HTTP/1.1\r\n\r\n",
	} {
		host, err := h.SniffData([]byte(wire))
		if err != nil || host != "sniff.test" {
			t.Errorf("host=%q err=%v", host, err)
		}
	}
}

func port12H2Frame(kind, flags byte, stream uint32, payload []byte) []byte {
	frame := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), kind, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(frame[5:], stream)
	return append(frame, payload...)
}
func TestSniffHTTP2ContinuationKeepsRelayBytes(t *testing.T) {
	authority := []byte("sniff.test")
	block := append([]byte{0x41, byte(len(authority))}, authority...)
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	settings := port12H2Frame(4, 0, 0, nil)
	headers := port12H2Frame(1, 0, 1, block[:4])
	continuation := port12H2Frame(9, 4, 1, block[4:])
	chunks := [][]byte{preface[:2], preface[2:], settings, headers, continuation}
	original := bytes.Join(chunks, nil)
	raw := &relayTestConn{chunks: chunks}
	conn := N.NewBufferedConn(raw)
	sd := port12Dispatcher(t, map[S.Type]SnifferConfig{S.HTTP: {OverrideDest: true}})
	metadata := port12Metadata(80)
	if !sd.TCPSniff(conn, metadata) || metadata.Host != "sniff.test" {
		t.Errorf("HTTP/2 continuation: host=%q sniff=%q", metadata.Host, metadata.SniffHost)
	}
	data, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatalf("HTTP/2 relay changed: err=%v", err)
	}
}

func TestSniffMalformedTLSDoesNotRequestPayload(t *testing.T) {
	for _, wire := range [][]byte{{0x16, 3, 3, 0x40, 1}, {0x16, 3, 3, 0x40, 0, 2}} {
		_, err := SniffTLS(wire)
		var need *errNeedAtLeastData
		if err == nil || errors.As(err, &need) {
			t.Errorf("invalid TLS header requested more data: %v", err)
		}
	}
}

func TestSniffSTUNBeforeQUICOnSharedPort(t *testing.T) {
	for _, withQUIC := range []bool{false, true} {
		name := "stun only"
		if withQUIC {
			name = "shared with quic"
		}
		t.Run(name, func(t *testing.T) {
			ports := utils.IntRanges[uint16]{utils.NewRange[uint16](443, 443)}
			protocols := map[S.Type]SnifferConfig{S.STUN: {Ports: ports}}
			if withQUIC {
				protocols[S.QUIC] = SnifferConfig{Ports: ports, OverrideDest: true}
			}
			sd := port12Dispatcher(t, protocols)
			metadata := port12Metadata(443)
			metadata.NetWork = C.UDP
			originalIP := metadata.DstIP
			wire := stunPacket(4, stunHeaderSize+4)
			udp := &fakeUDPPacket{data: wire, data2: bytes.Clone(wire)}
			packet := C.NewPacketAdapter(udp, metadata)
			sender := &fakeSender{}
			wrapped := sd.UDPSniff(packet, sender)
			if q, ok := wrapped.(*quicPacketSender); ok {
				defer q.close()
			}
			if metadata.SniffProtocol != "stun" || wrapped != sender {
				t.Errorf("STUN not detected before QUIC wrapper: protocol=%q sender=%T", metadata.SniffProtocol, wrapped)
			}
			if metadata.Host != "" || metadata.SniffHost != "" || metadata.DstIP != originalIP {
				t.Fatal("STUN detection changed destination")
			}
			if !bytes.Equal(wire, udp.data2) {
				t.Fatal("STUN detection changed packet data")
			}
			wrapped.Send(packet)
			if udp.data != nil {
				t.Fatal("underlying sender did not release packet")
			}
		})
	}
}

func TestSniffQUICAfterSTUNMiss(t *testing.T) {
	for _, override := range []bool{false, true} {
		name := "keep destination"
		if override {
			name = "override destination"
		}
		t.Run(name, func(t *testing.T) {
			sd := port12Dispatcher(t, map[S.Type]SnifferConfig{
				S.STUN: {OverrideDest: !override}, S.QUIC: {OverrideDest: override},
			})
			metadata := port12Metadata(443)
			metadata.NetWork = C.UDP
			originalIP := metadata.DstIP
			hello := makeTestClientHello("quic.test", 0)
			frames := quicvarint.Append([]byte{frameCrypto}, 0)
			frames = quicvarint.Append(frames, uint64(len(hello)))
			frames = append(frames, hello...)
			dcid := []byte("dispatch test")
			wire, _ := makeProtectedQUICInitialPacket(t, dcid, expandLabels(dcid, &quicV1), 0, 1, frames)
			packet := C.NewPacketAdapter(&fakeUDPPacket{data: wire, data2: bytes.Clone(wire)}, metadata)
			wrapped := sd.UDPSniff(packet, &fakeSender{})
			q, ok := wrapped.(*quicPacketSender)
			if !ok {
				t.Fatalf("QUIC wrapper was not selected: %T", wrapped)
			}
			defer q.close()
			wrapped.Send(packet)
			select {
			case <-q.done:
			default:
				t.Fatal("complete Initial did not finish sniffing")
			}
			if err := wrapped.DoSniff(metadata); err != nil {
				t.Fatal(err)
			}
			if metadata.SniffHost != "quic.test" || metadata.SniffProtocol != "" {
				t.Fatalf("unexpected metadata: %+v", metadata)
			}
			if override {
				if metadata.Host != "quic.test" || metadata.DstIP.IsValid() {
					t.Fatal("QUIC override policy lost")
				}
			} else if metadata.Host != "" || metadata.DstIP != originalIP {
				t.Fatal("STUN override policy leaked into QUIC result")
			}
		})
	}
}

func TestDispatcherRejectsUnknownSniffer(t *testing.T) {
	sd, err := NewDispatcher(&Config{Enable: true, Sniffers: map[S.Type]SnifferConfig{S.TLS: {}, S.Type(255): {}}})
	if !errors.Is(err, ErrorUnsupportedSniffer) || sd.Enable() {
		t.Fatalf("unknown protocol result: enabled=%v err=%v", sd.Enable(), err)
	}
}
