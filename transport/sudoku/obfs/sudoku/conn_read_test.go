package sudoku

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

// A peer may send its response as soon as the decoded request is complete.
// Any unread padding must not keep the request writer blocked at that point.
func TestConnPaddedRequestResponse(t *testing.T) {
	for _, mode := range []string{"prefer_ascii", "prefer_entropy"} {
		for _, padding := range []int{0, 100} {
			t.Run(fmt.Sprintf("%s/padding%d", mode, padding), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					left, right := net.Pipe()
					defer left.Close()
					defer right.Close()
					deadline := time.Now().Add(time.Second)
					_ = left.SetDeadline(deadline)
					_ = right.SetDeadline(deadline)
					table := NewTable("request-response-test", mode)
					client, server := NewConn(left, table, padding, padding, false), NewConn(right, table, padding, padding, false)
					client.rng, server.rng = newSudokuRand(1), newSudokuRand(2)
					request := bytes.Repeat([]byte{0x42}, 16)
					response := []byte("ok")
					done := make(chan error, 1)
					go func() {
						got := make([]byte, len(request))
						_, err := io.ReadFull(server, got)
						if err == nil && !bytes.Equal(got, request) {
							err = fmt.Errorf("request mismatch: %x", got)
						}
						if err == nil {
							_, err = server.Write(response)
						}
						done <- err
					}()
					_, writeErr := client.Write(request)
					got := make([]byte, len(response))
					var readErr error
					if writeErr == nil {
						_, readErr = io.ReadFull(client, got)
					} else {
						_ = left.Close()
					}
					serverErr := <-done
					if writeErr != nil || readErr != nil || serverErr != nil {
						t.Fatalf("request=%v response=%v server=%v", writeErr, readErr, serverErr)
					}
					if !bytes.Equal(got, response) {
						t.Fatalf("response = %q", got)
					}
				})
			})
		}
	}
}

func TestConnSmallReadsPreservePaddedPayload(t *testing.T) {
	table := NewTable("small-reads-test", "prefer_entropy")
	wire := &mockConn{}
	writer := NewConn(wire, table, 100, 100, false)
	writer.rng = newSudokuRand(3)
	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	reader := NewConn(&mockConn{readBuf: wire.writeBuf}, table, 0, 0, false)
	var got bytes.Buffer
	buf := make([]byte, 7)
	for {
		n, err := reader.Read(buf)
		got.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("payload corrupted: got %d bytes", got.Len())
	}
}
