package smux

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

func TestQueuedWriteOwnsPayloadAfterCancellation(t *testing.T) {
	for _, cause := range []string{"deadline", "close", "socket_error"} {
		t.Run(cause, func(t *testing.T) {
			s := &Session{shaper: make(chan writeRequest), die: make(chan struct{}), chSocketWriteError: make(chan struct{})}
			deadline := make(chan time.Time, 1)
			data := []byte("queued frame payload")
			original := bytes.Clone(data)
			f := newFrame(1, cmdPSH, 1)
			f.data = data
			finished := make(chan error, 1)
			go func() { _, err := s.writeFrameInternal(f, deadline, CLSDATA); finished <- err }()
			var queued writeRequest
			select {
			case queued = <-s.shaper:
			case <-time.After(time.Second):
				t.Fatal("write was not queued")
			}
			var want error = ErrTimeout
			switch cause {
			case "deadline":
				deadline <- time.Now()
			case "close":
				close(s.die)
				want = io.ErrClosedPipe
			case "socket_error":
				s.socketWriteError.Store(io.ErrUnexpectedEOF)
				close(s.chSocketWriteError)
				want = io.ErrUnexpectedEOF
			}
			select {
			case err := <-finished:
				if !errors.Is(err, want) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation blocked")
			}
			// io.Writer permits the caller to immediately reuse p after Write returns.
			for i := range data {
				data[i] = 'X'
			}
			if !bytes.Equal(queued.frame.data, original) {
				t.Fatal("queued frame aliases caller memory after cancellation")
			}
		})
	}
}
