package mux

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/yamux"
)

// CloseWrite on a yamux stream must only half-close it: the peer reads EOF
// and must still be able to deliver its response. metacubex/yamux implements
// Stream.Close() as CloseRead()+CloseWrite(), so mapping CloseWrite to Close
// loses the response.
func TestYamuxWrapStreamCloseWriteKeepsReadOpen(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	client, err := yamux.Client(clientPipe, yaMuxConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := yamux.Server(serverPipe, yaMuxConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	payload := bytes.Repeat([]byte{0x5a}, 64*1024)
	reply := []byte("received")

	serverDone := make(chan error, 1)
	go func() {
		s, err := server.AcceptStream()
		if err != nil {
			serverDone <- err
			return
		}
		stream := &yamuxWrapStream{s}
		defer stream.Close()
		got, err := io.ReadAll(stream)
		if err != nil {
			serverDone <- err
			return
		}
		if len(got) != len(payload) {
			serverDone <- fmt.Errorf("server read %d bytes, want %d", len(got), len(payload))
			return
		}
		_, err = stream.Write(reply)
		serverDone <- err
	}()

	s, err := client.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stream := &yamuxWrapStream{s}
	defer stream.Close()
	if _, err = stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err = stream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("read response after CloseWrite: %v", err)
	}
	if !bytes.Equal(got, reply) {
		t.Fatalf("response = %q, want %q", got, reply)
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}
