package net_test

import (
	"io"
	"net"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
)

func TestCachedConnReadCachedTransfersRemainingData(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(time.Second))
	conn := N.NewCachedConn(left, []byte("prefix"))
	first := make([]byte, 2)
	if _, err := io.ReadFull(conn, first); err != nil {
		t.Fatal(err)
	}
	if string(first) != "pr" {
		t.Fatalf("first read: %q", first)
	}
	if conn.ReaderReplaceable() {
		t.Fatal("unread cache was skipped")
	}
	cached := conn.ReadCached()
	if cached == nil {
		t.Fatal("missing remaining cache")
	}
	defer cached.Release()
	if string(cached.Bytes()) != "efix" {
		t.Fatalf("remaining cache: %q", cached.Bytes())
	}
	if again := conn.ReadCached(); again != nil {
		t.Fatal("cached data was returned twice")
	}
	if !conn.ReaderReplaceable() {
		t.Fatal("consumed cache still blocks direct reads")
	}
	done := make(chan error, 1)
	go func() { _, err := right.Write([]byte("tail")); done <- err }()
	data := make([]byte, 4)
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "tail" {
		t.Fatalf("read after cache: %q", data)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
