package session

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/skiplist"
	"github.com/metacubex/mihomo/transport/anytls/util"
)

func testPadding() *atomic.Pointer[padding.PaddingFactory] {
	p := new(atomic.Pointer[padding.PaddingFactory])
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, p)
	return p
}

func TestAnyTLSClientMetadata(t *testing.T) {
	for _, metadata := range []string{"", "custom-client/1"} {
		t.Run("metadata="+metadata, func(t *testing.T) {
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			local.SetDeadline(time.Now().Add(3 * time.Second))
			remote.SetDeadline(time.Now().Add(3 * time.Second))
			received := make(chan util.StringMap, 1)
			go func() {
				var hdr rawHeader
				if _, err := io.ReadFull(remote, hdr[:]); err != nil || hdr.Cmd() != cmdSettings {
					received <- nil
					return
				}
				data := make([]byte, hdr.Length())
				if _, err := io.ReadFull(remote, data); err != nil {
					received <- nil
					return
				}
				received <- util.StringMapFromBytes(data)
				io.Copy(io.Discard, remote)
			}()
			c := NewClient(context.Background(), func(context.Context) (net.Conn, error) { return local, nil }, testPadding(), metadata, time.Minute, time.Minute, 0, false)
			defer c.Close()
			s, err := c.CreateStream(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			settings := <-received
			if settings == nil || settings["client"] != metadata || settings["v"] != "2" || settings["padding-md5"] == "" {
				t.Fatalf("unexpected settings: %v", settings)
			}
		})
	}
}

func TestAnyTLSClientReuse(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run("disabled="+strconv.FormatBool(disabled), func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			var accepted atomic.Int32
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				for {
					raw, err := l.Accept()
					if err != nil {
						return
					}
					accepted.Add(1)
					wg.Go(func() {
						server := NewServerSession(raw, func(s *Stream) {
							defer s.Close()
							if s.HandshakeSuccess() == nil {
								io.Copy(s, s)
							}
						}, testPadding())
						server.Run()
					})
				}
			}()
			c := NewClient(context.Background(), func(ctx context.Context) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
			}, testPadding(), "", time.Minute, time.Minute, 0, disabled)
			defer func() { c.Close(); l.Close(); <-finished; wg.Wait() }()
			for i := 0; i < 3; i++ {
				s, err := c.CreateStream(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				s.SetDeadline(time.Now().Add(5 * time.Second))
				payload := bytes.Repeat([]byte{byte(i + 1)}, 131081)
				written := make(chan error, 1)
				go func() { _, err := s.Write(payload); written <- err }()
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(s, got); err != nil {
					t.Fatal(err)
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatal("payload changed")
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			want := int32(1)
			if disabled {
				want = 3
			}
			if got := accepted.Load(); got != want {
				t.Fatalf("physical sessions=%d, want %d", got, want)
			}
			c.sessionsLock.Lock()
			remaining := len(c.sessions)
			c.sessionsLock.Unlock()
			if disabled && remaining != 0 {
				t.Fatalf("%d sessions remain with reuse disabled", remaining)
			}
		})
	}
}

func TestAnyTLSClientCloseDuringDial(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run("disabled="+strconv.FormatBool(disabled), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			c := NewClient(context.Background(), func(ctx context.Context) (net.Conn, error) { close(entered); <-release; return local, nil }, testPadding(), "", time.Minute, time.Minute, 0, disabled)
			defer c.Close()
			result := make(chan error, 1)
			go func() {
				_, err := c.CreateStream(context.Background())
				result <- err
			}()
			<-entered
			c.Close()
			close(release)
			if err := <-result; err == nil {
				t.Error("dial completion resurrected a closed client")
			}
			remote.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := remote.Read(make([]byte, 1)); err != io.EOF {
				t.Errorf("late connection was not closed: %v", err)
			}
		})
	}
}

func TestAnyTLSClientCancelsHandshake(t *testing.T) {
	for _, callerCancels := range []bool{false, true} {
		t.Run("caller-cancels="+strconv.FormatBool(callerCancels), func(t *testing.T) {
			entered := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := NewClient(context.Background(), func(ctx context.Context) (net.Conn, error) { close(entered); <-ctx.Done(); return nil, ctx.Err() }, testPadding(), "", time.Minute, time.Minute, 0, true)
			defer c.Close()
			result := make(chan error, 1)
			go func() { _, err := c.CreateStream(ctx); result <- err }()
			<-entered
			if callerCancels {
				cancel()
			} else {
				c.Close()
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("canceled handshake succeeded")
				}
			case <-time.After(time.Second):
				cancel()
				t.Fatal("handshake ignored client close")
			}
		})
	}
}

func TestIdleCleanupConcurrentPoolRemoval(t *testing.T) {
	c := &Client{idleSession: skiplist.NewSkipList[uint64, *Session]()}
	session := &Session{idleSince: time.Now()}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		for range 10000 {
			c.idleSessionLock.Lock()
			c.idleSession.Insert(1, session)
			c.idleSession.Remove(1)
			c.idleSessionLock.Unlock()
		}
	})
	wg.Go(func() {
		<-start
		for range 10000 {
			c.idleCleanupExpTime(time.Time{})
		}
	})
	close(start)
	wg.Wait()
	if c.idleSession.Len() != 0 {
		t.Fatal("removed session remained in the idle pool")
	}
}
