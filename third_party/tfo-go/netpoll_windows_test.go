package tfo

import (
	"context"
	"net"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestWindowsFDLayoutAndFallback(t *testing.T) {
	fd := reflect.TypeOf(net.TCPConn{}).Field(0).Type.Field(0).Type.Elem()
	pfd, _ := fd.FieldByName("pfd")
	_, modernLayout := pfd.Type.FieldByName("KeepFileCompletionModes")
	if modernLayout && !checkWindowsFDLayout() {
		t.Fatal("current Windows socket layout must retain TCP Fast Open")
	}
	previous := windowsFDLayoutCompatible
	windowsFDLayoutCompatible = false
	t.Cleanup(func() { windowsFDLayoutCompatible = previous })
	var controls atomic.Int32
	d := Dialer{Dialer: net.Dialer{
		Timeout:   5 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.IPv6loopback},
		ControlContext: func(ctx context.Context, network, address string, raw syscall.RawConn) error {
			controls.Add(1)
			return nil
		},
	}}
	testClientWriteReadServerReadWrite(t, ListenConfig{DisableTFO: true}, d)
	if controls.Load() != 1 {
		t.Fatalf("fallback ControlContext calls = %d, want 1", controls.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := d.DialContext(ctx, "tcp", "[::1]:1", hello); err == nil || conn != nil {
		t.Fatalf("canceled fallback returned connection=%v error=%v", conn, err)
	}
}
