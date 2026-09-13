package restls

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestConfigRejectsMalformedScripts(t *testing.T) {
	for _, script := range []string{"32768", "40000", "1~32768", "32767~2", "1<255", "1<300", "1<1junk", "12x"} {
		t.Run(script, func(t *testing.T) {
			// Invalid profile input must be returned to the caller, never panic.
			defer func() {
				if value := recover(); value != nil {
					t.Errorf("script parsing panicked: %v", value)
				}
			}()
			config, err := NewRestlsConfig("restls.test", "password", "tls13", script, "chrome")
			if err == nil || config != nil {
				t.Fatalf("malformed script accepted: config present=%v err=%v", config != nil, err)
			}
		})
	}
	for _, script := range []string{"", "0", "32767", "32767~1", "1<254", "300?100<1,400~100,350~100,600~100,300~200,300~100"} {
		t.Run("valid_"+script, func(t *testing.T) {
			if _, err := NewRestlsConfig("restls.test", "password", "tls13", script, "chrome"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConcurrentHandshakesKeepSharedConfig(t *testing.T) {
	config, err := NewRestlsConfig("restls.test", "password", "tls13", "", "chrome")
	if err != nil {
		t.Fatal(err)
	}
	cache, clientID := config.ClientSessionCache, config.ClientID
	const clients = 12
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range clients {
		wg.Go(func() {
			client, peer := net.Pipe()
			defer client.Close()
			drained := make(chan struct{})
			go func() { defer close(drained); defer peer.Close(); _, _ = io.Copy(io.Discard, peer) }()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			conn, err := NewRestls(ctx, client, config)
			if err == nil || conn != nil {
				t.Error("handshake to a peer without TLS unexpectedly succeeded")
			}
			client.Close()
			<-drained
		})
	}
	close(start)
	wg.Wait()
	if config.MinVersion != 0 || config.MaxVersion != 0 {
		t.Errorf("handshake modified shared TLS bounds: min=%x max=%x", config.MinVersion, config.MaxVersion)
	}
	if config.ClientSessionCache != cache || config.ClientID != clientID {
		t.Error("shared session cache or fingerprint state was replaced")
	}
}
