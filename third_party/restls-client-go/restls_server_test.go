package tls

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestRestlsServerTLS13(t *testing.T) {
	testRestlsServerRoundTripForClientIDMap(t, VersionTLS13, "tls13")
}

func TestRestlsServerTLS12(t *testing.T) {
	testRestlsServerRoundTripForClientIDMap(t, VersionTLS12, "tls12")
}

func TestRestlsServerTLS12Resumption(t *testing.T) {
	const password = "restls-server-test-password"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targetConfig := testConfig.Clone()
	targetConfig.MinVersion = VersionTLS12
	targetConfig.MaxVersion = VersionTLS12
	targetConfig.SessionTicketsDisabled = false
	targetConfig.Certificates = append([]Certificate(nil), testConfig.Certificates...)
	targetConfig.SessionTicketKey = [32]byte{
		0x52, 0x65, 0x73, 0x74, 0x6c, 0x73, 0x20, 0x54,
		0x4c, 0x53, 0x31, 0x32, 0x20, 0x52, 0x65, 0x73,
		0x75, 0x6d, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x20,
		0x54, 0x65, 0x73, 0x74, 0x20, 0x4b, 0x65, 0x79,
	}

	targetResumed := make(chan bool, 2)
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				tlsConn := Server(conn, targetConfig)
				defer tlsConn.Close()
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				targetResumed <- tlsConn.ConnectionState().DidResume
				_, _ = io.Copy(io.Discard, tlsConn)
			}(conn)
		}
	}()
	defer func() {
		ln.Close()
		<-targetDone
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverConfig := &RestlsServerConfig{
		ServerHostname: ln.Addr().String(),
		Password:       password,
	}

	clientConfig := newRestlsServerTestClientConfig(t, password, "tls12", "", "chrome", VersionTLS12)
	clientConfig.Time = func() time.Time { return time.Unix(0, 0) }

	first := testRestlsServerRoundTripWithConfig(t, ctx, serverConfig, clientConfig, "chrome")
	if first.DidResume {
		t.Fatal("first Restls client connection unexpectedly resumed")
	}
	if resumed := readRestlsTargetResumed(t, targetResumed); resumed {
		t.Fatal("first target TLS connection unexpectedly resumed")
	}

	second := testRestlsServerRoundTripWithConfig(t, ctx, serverConfig, clientConfig, "chrome")
	if !second.DidResume {
		t.Fatal("second Restls client connection did not resume")
	}
	if resumed := readRestlsTargetResumed(t, targetResumed); !resumed {
		t.Fatal("second target TLS connection did not resume")
	}
}

func TestRestlsServerFallbackTLS12(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targetConfig := testConfig.Clone()
	targetConfig.MinVersion = VersionTLS12
	targetConfig.MaxVersion = VersionTLS12
	targetConfig.SessionTicketsDisabled = false
	targetConfig.Certificates = append([]Certificate(nil), testConfig.Certificates...)
	targetConfig.SessionTicketKey = [32]byte{
		0x46, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b,
		0x20, 0x54, 0x4c, 0x53, 0x31, 0x32, 0x20, 0x53,
		0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x54,
		0x69, 0x63, 0x6b, 0x65, 0x74, 0x20, 0x4b, 0x65,
	}

	targetResumed := make(chan bool, 2)
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				tlsConn := Server(conn, targetConfig)
				defer tlsConn.Close()
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				targetResumed <- tlsConn.ConnectionState().DidResume
				request := make([]byte, len("ping"))
				if _, err := io.ReadFull(tlsConn, request); err != nil || string(request) != "ping" {
					return
				}
				if _, err := tlsConn.Write([]byte("pong")); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, tlsConn)
			}(conn)
		}
	}()
	defer func() {
		ln.Close()
		<-targetDone
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverConfig := &RestlsServerConfig{
		ServerHostname: ln.Addr().String(),
		Password:       "fallback-must-not-authenticate",
	}
	sessionCache := NewLRUClientSessionCache(1)
	clientConfig := &Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		MinVersion:         VersionTLS12,
		MaxVersion:         VersionTLS12,
		ClientSessionCache: sessionCache,
		Time:               func() time.Time { return time.Unix(0, 0) },
	}

	testRestlsServerFallbackRoundTrip(t, ctx, serverConfig, clientConfig)
	if resumed := readRestlsTargetResumed(t, targetResumed); resumed {
		t.Fatal("first ordinary TLS connection unexpectedly resumed")
	}
	if _, ok := sessionCache.Get("example.com"); !ok {
		t.Fatal("ordinary TLS client did not cache the target session")
	}
	testRestlsServerFallbackRoundTrip(t, ctx, serverConfig, clientConfig)
	if resumed := readRestlsTargetResumed(t, targetResumed); !resumed {
		t.Fatal("second ordinary TLS connection did not resume")
	}
}

func TestRestlsServerFallbackNonTLS(t *testing.T) {
	const request = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"
	const response = "HTTP/1.0 204 No Content\r\n\r\n"
	targetDone := make(chan error, 1)
	serverConfig := &RestlsServerConfig{
		ServerHostname: "example.com:443",
		Password:       "fallback-must-not-authenticate",
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			serverConn, targetConn := net.Pipe()
			go func() {
				defer targetConn.Close()
				got := make([]byte, len(request))
				if _, err := io.ReadFull(targetConn, got); err != nil {
					targetDone <- err
					return
				}
				if string(got) != request {
					targetDone <- fmt.Errorf("fallback target read = %q, want %q", got, request)
					return
				}
				_, err := targetConn.Write([]byte(response))
				targetDone <- err
			}()
			return serverConn, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientConn, serverConn := localPipe(t)
	defer clientConn.Close()
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		conn, err := RestlsServer(ctx, serverConn, serverConfig)
		if conn != nil {
			_ = conn.Close()
			serverDone <- errors.New("non-TLS fallback returned a Restls connection")
			return
		}
		serverDone <- err
	}()

	if _, err := io.WriteString(clientConn, request); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(response))
	if _, err := io.ReadFull(clientConn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != response {
		t.Fatalf("fallback response = %q, want %q", got, response)
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
	clientConn.Close()
	select {
	case err := <-serverDone:
		if err == nil {
			t.Fatal("non-TLS fallback returned nil error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("non-TLS fallback did not finish")
	}
}

func TestHandshakeMessageReaderAcrossRecords(t *testing.T) {
	certificate := []byte{typeCertificate, 0, 0, 6, 1, 2, 3, 4, 5, 6}
	helloDone := []byte{typeServerHelloDone, 0, 0, 0}
	flight := append(append([]byte(nil), certificate...), helloDone...)
	split := len(certificate) - 2

	var messages handshakeMessageReader
	var got []uint8
	if err := messages.addRecord(restlsServerTestRecord(recordTypeHandshake, flight[:split]), func(msg []byte) bool {
		got = append(got, msg[0])
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("messages before reassembly = %v, want none", got)
	}
	if err := messages.addRecord(restlsServerTestRecord(recordTypeHandshake, flight[split:]), func(msg []byte) bool {
		got = append(got, msg[0])
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != typeCertificate || got[1] != typeServerHelloDone {
		t.Fatalf("reassembled message types = %v, want [%d %d]", got, typeCertificate, typeServerHelloDone)
	}
}

func TestRestlsServerTLS12FragmentedServerHelloDone(t *testing.T) {
	hello, err := (&serverHelloMsg{
		vers:              VersionTLS12,
		random:            make([]byte, 32),
		cipherSuite:       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		compressionMethod: compressionNone,
	}).marshal()
	if err != nil {
		t.Fatal(err)
	}
	helloDone := []byte{typeServerHelloDone, 0, 0, 0}
	firstPayload := append(append([]byte(nil), hello...), helloDone[:3]...)
	firstRecord := restlsServerTestRecord(recordTypeHandshake, firstPayload)
	lastRecord := restlsServerTestRecord(recordTypeHandshake, helloDone[3:])

	inbound, client := net.Pipe()
	target, targetPeer := net.Pipe()
	defer inbound.Close()
	defer client.Close()
	defer target.Close()
	defer targetPeer.Close()
	deadline := time.Now().Add(5 * time.Second)
	for _, conn := range []net.Conn{inbound, client, target, targetPeer} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}

	state := newRestlsServerUnitState(t, "")
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- state.handshakeTLS12(inbound, target, firstRecord)
	}()
	targetDone := make(chan error, 1)
	go func() {
		if _, err := targetPeer.Write(lastRecord); err != nil {
			targetDone <- err
			return
		}
		for i := 0; i < 3; i++ {
			if _, err := readTLSRecord(targetPeer); err != nil {
				targetDone <- err
				return
			}
		}
		targetDone <- nil
	}()

	if got, err := readTLSRecord(client); err != nil {
		t.Fatal(err)
	} else if string(got) != string(lastRecord) {
		t.Fatalf("forwarded fragmented record = %x, want %x", got, lastRecord)
	}
	clientFlight := [][]byte{
		restlsServerTestRecord(recordTypeHandshake, []byte{typeClientKeyExchange, 0, 0, 0}),
		{byte(recordTypeChangeCipherSpec), 0x03, 0x03, 0, 1, 1},
		restlsServerTestRecord(recordTypeHandshake, []byte{typeFinished, 0, 0, 0}),
	}
	for _, record := range clientFlight {
		if _, err := client.Write(record); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverDone:
		if err == nil || !strings.Contains(err.Error(), "was not authenticated") {
			t.Fatalf("handshake error = %v, want authentication failure", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fragmented ServerHelloDone was not detected")
	}
}

func TestRestlsServerTLS13ClientCertificateRequest(t *testing.T) {
	targetAddr, stopTarget := startRestlsTestTLSTarget(t, VersionTLS13, func(config *Config) {
		config.ClientAuth = RequestClientCert
	})
	defer stopTarget()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const password = "restls-server-test-password"
	serverConfig := &RestlsServerConfig{
		ServerHostname: targetAddr,
		Password:       password,
	}

	clientConfig := newRestlsServerTestClientConfig(t, password, "tls13", "", "chrome", VersionTLS13)

	testRestlsServerRoundTripWithConfig(t, ctx, serverConfig, clientConfig, "chrome")
}

func TestRestlsServerTLS13NetPipeTarget(t *testing.T) {
	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		go func() {
			config := testConfig.Clone()
			config.MinVersion = VersionTLS13
			config.MaxVersion = VersionTLS13
			config.Certificates = append([]Certificate(nil), testConfig.Certificates...)
			tlsConn := Server(serverConn, config)
			defer tlsConn.Close()
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, tlsConn)
		}()
		return clientConn, nil
	}
	testRestlsServerRoundTrip(t, VersionTLS13, "tls13", "chrome", "", dialContext)
}

func TestRestlsServerResponseCommandWaitsForClientRecord(t *testing.T) {
	state := newRestlsServerUnitState(t, "1<1,1")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		done <- state.writeRestlsRecords(server, []byte("ab"))
	}()

	if _, err := readTLSRecord(client); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("write completed before client record: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	state.noteClientRecord()
	if _, err := readTLSRecord(client); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("write did not resume after client record")
	}
}

func TestRestlsServerFakeResponseDoesNotWaitForClientRecord(t *testing.T) {
	state := newRestlsServerUnitState(t, "15<1,15")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	fakeDone := make(chan error, 1)
	go func() {
		fakeDone <- state.writeRestlsRecords(server, nil)
	}()
	if _, err := readTLSRecord(client); err != nil {
		t.Fatal(err)
	}
	if err := waitRestlsServerDone(t, fakeDone); err != nil {
		t.Fatal(err)
	}

	realDone := make(chan error, 1)
	go func() {
		realDone <- state.writeRestlsRecords(server, []byte("x"))
	}()
	if _, err := readTLSRecord(client); err != nil {
		t.Fatal(err)
	}
	if err := waitRestlsServerDone(t, realDone); err != nil {
		t.Fatal(err)
	}
}

func TestRestlsServerWriteTargetRecordParrotsTLS12GCMNonce(t *testing.T) {
	state := newRestlsServerUnitState(t, "")
	state.parrotGCM = true
	state.toClientCounter = 41

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	record := []byte{0x17, 0x03, 0x03, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0}
	done := make(chan error, 1)
	go func() {
		done <- state.writeTargetRecord(server, append([]byte(nil), record...))
	}()

	got, err := readTLSRecord(client)
	if err != nil {
		t.Fatal(err)
	}
	if nonce := binary.BigEndian.Uint64(got[recordHeaderLen : recordHeaderLen+8]); nonce != 42 {
		t.Fatalf("nonce = %d, want 42", nonce)
	}
	if err := waitRestlsServerDone(t, done); err != nil {
		t.Fatal(err)
	}
	if state.toClientCounter != 42 {
		t.Fatalf("toClientCounter = %d, want 42", state.toClientCounter)
	}
}

func TestRestlsServerQuestionMarkScriptStableAcrossConnections(t *testing.T) {
	const script = "1?32760"
	restlsServerScriptCache.Delete(script)
	first := newRestlsServerUnitState(t, script)
	if len(first.script) != 1 || first.script[0].targetLen[1] != 0 {
		t.Fatalf("script = %#v, want one fixed-length line", first.script)
	}
	want := first.script[0].targetLen[0]

	for i := 0; i < 20; i++ {
		state := newRestlsServerUnitState(t, script)
		if got := state.script[0].targetLen[0]; got != want {
			t.Fatalf("connection %d target length = %d, want cached %d", i, got, want)
		}
	}
}

func TestRestlsServerCloseNotify(t *testing.T) {
	for _, tt := range []struct {
		name        string
		version     uint16
		versionHint string
	}{
		{name: "tls12", version: VersionTLS12, versionHint: "tls12"},
		{name: "tls13", version: VersionTLS13, versionHint: "tls13"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			targetAddr, stopTarget := startRestlsTestTLSTarget(t, tt.version, nil)
			defer stopTarget()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			const password = "restls-server-test-password"
			serverConfig := &RestlsServerConfig{
				ServerHostname: targetAddr,
				Password:       password,
			}
			serverConfig.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, address)
			}

			clientConfig := newRestlsServerTestClientConfig(t, password, tt.versionHint, "", "chrome", tt.version)

			clientConn, serverSideConn := localPipe(t)
			serverDone := make(chan error, 1)
			go func() {
				serverConn, err := RestlsServer(ctx, serverSideConn, serverConfig)
				if err != nil {
					serverDone <- err
					return
				}
				buf := make([]byte, len("request"))
				if _, err := io.ReadFull(serverConn, buf); err != nil {
					_ = serverConn.Close()
					serverDone <- err
					return
				}
				if string(buf) != "request" {
					_ = serverConn.Close()
					serverDone <- fmt.Errorf("server read = %q, want request", buf)
					return
				}
				if _, err := serverConn.Write([]byte("response")); err != nil {
					_ = serverConn.Close()
					serverDone <- err
					return
				}
				serverDone <- serverConn.Close()
			}()

			clientHelloID := *clientIDMap["chrome"]
			client := UClient(clientConn, clientConfig, clientHelloID)
			if err := client.Handshake(); err != nil {
				_ = client.Close()
				t.Fatalf("client handshake failed: %v", err)
			}
			if _, err := client.Write([]byte("request")); err != nil {
				_ = client.Close()
				t.Fatalf("client write failed: %v", err)
			}
			buf := make([]byte, len("response"))
			if _, err := io.ReadFull(client, buf); err != nil {
				_ = client.Close()
				t.Fatalf("client read response failed: %v", err)
			}
			if string(buf) != "response" {
				_ = client.Close()
				t.Fatalf("client read = %q, want response", buf)
			}
			if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				_ = client.Close()
				t.Fatalf("client read after server close = %d, %v; want 0, EOF", n, err)
			}
			if err := client.Close(); err != nil {
				t.Fatalf("client close failed: %v", err)
			}

			select {
			case err := <-serverDone:
				if err != nil {
					t.Fatalf("server failed: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server timed out")
			}
		})
	}
}

func TestNewRateLimitedConnDisabled(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	if limited := newRateLimitedConn(conn, 0); limited != conn {
		t.Fatal("zero rate limit wrapped connection")
	}
}

func TestRateLimitedConnBurst(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	limited := newRateLimitedConn(conn, 800).(*rateLimitedConn)
	defer limited.Close()
	if limited.burst != 1 {
		t.Fatalf("burst = %d, want 1", limited.burst)
	}
}

func TestBitRateLimiterReservations(t *testing.T) {
	limiter := &bitRateLimiter{rateBps: 800}
	now := time.Unix(0, 0)
	if delay := limiter.reserveN(now, 1); delay != 0 {
		t.Fatalf("initial reservation delay = %s, want 0", delay)
	}
	if delay := limiter.reserveN(now, 1); delay != 10*time.Millisecond {
		t.Fatalf("second reservation delay = %s, want 10ms", delay)
	}
}

func TestBitRateLimiterCancellation(t *testing.T) {
	limiter := &bitRateLimiter{rateBps: 8}
	limiter.reserveN(time.Now(), 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.WaitN(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitN error = %v, want context.Canceled", err)
	}
}

func testRestlsServerRoundTripForClientIDMap(t *testing.T, version uint16, versionHint string) {
	t.Helper()

	scripts := []struct {
		name string
		text string
	}{
		{name: "default", text: ""},
		{name: "fixed", text: "1500"},
		{name: "random_range", text: "1200~128"},
		{name: "fixed_random", text: "900?128"},
		{name: "empty_then_fixed", text: "0,1500"},
		{name: "response", text: "1500<1"},
	}

	clientIDs := make([]string, 0, len(clientIDMap))
	for clientID := range clientIDMap {
		clientIDs = append(clientIDs, clientID)
	}
	sort.Strings(clientIDs)

	for _, clientID := range clientIDs {
		t.Run(clientID, func(t *testing.T) {
			for _, script := range scripts {
				t.Run(script.name, func(t *testing.T) {
					testRestlsServerRoundTrip(t, version, versionHint, clientID, script.text, nil)
				})
			}
		})
	}
}

func testRestlsServerRoundTrip(t *testing.T, version uint16, versionHint, clientIDName, script string, dialContext func(ctx context.Context, network, address string) (net.Conn, error)) {
	t.Helper()

	targetAddr := "example.com:443"
	if dialContext == nil {
		var stopTarget func()
		targetAddr, stopTarget = startRestlsTestTLSTarget(t, version, nil)
		defer stopTarget()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const password = "restls-server-test-password"
	serverConfig := &RestlsServerConfig{
		ServerHostname: targetAddr,
		Password:       password,
		RestlsScript:   script,
	}
	dialed := make(chan string, 1)
	serverConfig.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed <- address
		if dialContext != nil {
			return dialContext(ctx, network, address)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}

	clientConfig := newRestlsServerTestClientConfig(t, password, versionHint, script, clientIDName, version)

	testRestlsServerRoundTripWithConfig(t, ctx, serverConfig, clientConfig, clientIDName)

	gotDial := map[string]bool{}
	select {
	case addr := <-dialed:
		gotDial[addr] = true
	default:
	}
	if !gotDial[targetAddr] {
		t.Fatalf("DialContext calls = %v, want target %q", gotDial, targetAddr)
	}
}

func readRestlsTargetResumed(t *testing.T, resumed <-chan bool) bool {
	t.Helper()
	select {
	case didResume := <-resumed:
		return didResume
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for target TLS resumption state")
		return false
	}
}

func testRestlsServerRoundTripWithConfig(t *testing.T, ctx context.Context, serverConfig *RestlsServerConfig, clientConfig *Config, clientIDName string) ConnectionState {
	t.Helper()

	clientConn, serverSideConn := localPipe(t)
	serverDone := make(chan error, 1)
	closeServer := make(chan struct{})
	exchanges := restlsServerTestExchanges()
	go func() {
		serverConn, err := RestlsServer(ctx, serverSideConn, serverConfig)
		if err != nil {
			serverDone <- err
			return
		}
		defer serverConn.Close()
		for i, exchange := range exchanges {
			buf := make([]byte, len(exchange.client))
			if _, err := io.ReadFull(serverConn, buf); err != nil {
				serverDone <- fmt.Errorf("read exchange %d: %w", i, err)
				return
			}
			if string(buf) != exchange.client {
				serverDone <- fmt.Errorf("read exchange %d = %q, want %q", i, buf, exchange.client)
				return
			}
			if _, err = serverConn.Write([]byte(exchange.server)); err != nil {
				serverDone <- fmt.Errorf("write exchange %d: %w", i, err)
				return
			}
		}
		select {
		case <-closeServer:
			serverDone <- nil
		case <-ctx.Done():
			serverDone <- ctx.Err()
		}
	}()

	clientHelloID := *clientIDMap[clientIDName]
	client := UClient(clientConn, clientConfig, clientHelloID)
	defer client.Close()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	state := client.ConnectionState()
	for i, exchange := range exchanges {
		if _, err := client.Write([]byte(exchange.client)); err != nil {
			t.Fatalf("client write exchange %d failed: %v", i, err)
		}
		buf := make([]byte, len(exchange.server))
		if _, err := io.ReadFull(client, buf); err != nil {
			t.Fatalf("client read exchange %d failed: %v", i, err)
		}
		if string(buf) != exchange.server {
			t.Fatalf("client read exchange %d = %q, want %q", i, buf, exchange.server)
		}
	}
	close(closeServer)
	client.Close()

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server timed out")
	}
	return state
}

func testRestlsServerFallbackRoundTrip(t *testing.T, ctx context.Context, serverConfig *RestlsServerConfig, clientConfig *Config) {
	t.Helper()
	clientConn, serverConn := localPipe(t)
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		conn, err := RestlsServer(ctx, serverConn, serverConfig)
		if conn != nil {
			_ = conn.Close()
			serverDone <- errors.New("ordinary TLS fallback returned a Restls connection")
			return
		}
		serverDone <- err
	}()

	client := Client(clientConn, clientConfig)
	if err := client.Handshake(); err != nil {
		_ = client.Close()
		t.Fatalf("ordinary TLS handshake through fallback failed: %v", err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		_ = client.Close()
		t.Fatalf("ordinary TLS fallback write failed: %v", err)
	}
	response := make([]byte, len("pong"))
	if _, err := io.ReadFull(client, response); err != nil {
		_ = client.Close()
		t.Fatalf("ordinary TLS fallback read failed: %v", err)
	}
	if string(response) != "pong" {
		_ = client.Close()
		t.Fatalf("ordinary TLS fallback read = %q, want pong", response)
	}
	_ = client.Close()

	select {
	case err := <-serverDone:
		if err == nil {
			t.Fatal("ordinary TLS fallback returned nil error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ordinary TLS fallback did not finish")
	}
}

func newRestlsServerTestClientConfig(t testing.TB, password, versionHint, script, clientIDName string, version uint16) *Config {
	t.Helper()
	config, err := NewRestlsConfig("example.com", password, versionHint, script, clientIDName)
	if err != nil {
		t.Fatal(err)
	}
	config.InsecureSkipVerify = true
	config.MinVersion = version
	config.MaxVersion = version
	return config
}

func newRestlsServerUnitState(t testing.TB, script string) *restlsServerState {
	t.Helper()
	state, err := newRestlsServerState(&RestlsServerConfig{
		Password:     "restls-server-unit-test-password",
		RestlsScript: script,
		MinRecordLen: 15,
	})
	if err != nil {
		t.Fatal(err)
	}
	state.serverRandom = make([]byte, 32)
	return state
}

func waitRestlsServerDone(t testing.TB, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Restls server operation")
		return nil
	}
}

func restlsServerTestExchanges() []struct {
	client string
	server string
} {
	return []struct {
		client string
		server string
	}{
		{client: "ping", server: "pong"},
		{client: "second-request", server: "second-response"},
		{client: "short", server: "ok"},
		{
			client: "client-block-" + strings.Repeat("c", 2048),
			server: "server-block-" + strings.Repeat("s", 32768),
		},
	}
}

func restlsServerTestRecord(typ recordType, payload []byte) []byte {
	record := make([]byte, recordHeaderLen+len(payload))
	record[0] = byte(typ)
	record[1] = 0x03
	record[2] = 0x03
	record[3] = byte(len(payload) >> 8)
	record[4] = byte(len(payload))
	copy(record[recordHeaderLen:], payload)
	return record
}

func startRestlsTestTLSTarget(t *testing.T, version uint16, configure func(*Config)) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				config := testConfig.Clone()
				config.MinVersion = version
				config.MaxVersion = version
				config.Certificates = append([]Certificate(nil), testConfig.Certificates...)
				if configure != nil {
					configure(config)
				}
				tlsConn := Server(conn, config)
				defer tlsConn.Close()
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, tlsConn)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		ln.Close()
		<-done
	}
}
