package outbound

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/tls"
)

// Inspect the adapter's actual Initial packet without contacting a MASQUE service.
func TestMasqueDialUsesFullConnectionID(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	base := NewBase(BaseOption{Addr: server.LocalAddr().String()})
	base.dialer = dialer.NewDialer()
	outbound := &Masque{Base: base, tlsConfig: &tls.Config{ServerName: "masque.test", NextProtos: []string{"h3"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		pc, conn, err := outbound.dialQuic(ctx)
		if pc != nil {
			_ = pc.Close()
		}
		if conn != nil {
			_ = conn.CloseWithError(0, "test complete")
		}
		result <- err
	}()
	buf := make([]byte, 2048)
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	dialErr := <-result
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("cancelled dial = %v", dialErr)
	}
	if n < 7 || buf[0]&0x80 == 0 {
		t.Fatalf("invalid initial packet: %x", buf[:n])
	}
	sourceOffset := 6 + int(buf[5])
	if sourceOffset >= n {
		t.Fatal("truncated destination ID")
	}
	if got := int(buf[sourceOffset]); got != 20 {
		t.Fatalf("MASQUE source connection ID length = %d, want 20", got)
	}
}
