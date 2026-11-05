package inbound_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestHttpTestTunnelCloseReleasesConnections(t *testing.T) {
	const scenarioKey = "MIHOMO_HTTP_TEST_TUNNEL_CLOSE_REPRO"
	scenario := os.Getenv(scenarioKey)
	if scenario == "" {
		for _, name := range []string{"accepted-keepalive", "late-handoff"} {
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHttpTestTunnelCloseReleasesConnections$", "-test.count=1")
				cmd.Env = append(os.Environ(), scenarioKey+"="+name)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("isolated %s regression failed: %v\n%s", name, err, output)
				}
			})
		}
		return
	}

	// A broken handoff cannot be released by closing its pipe, so isolate it
	// in a subprocess rather than leaving a blocked goroutine in the suite.
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if scenario == "late-handoff" {
		if err := tunnel.Close(); err != nil {
			t.Fatal(err)
		}
	}
	finished := make(chan struct{})
	go func() {
		tunnel.HandleTCPConn(server, &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 80})
		close(finished)
	}()
	if scenario == "accepted-keepalive" {
		_, err := fmt.Fprintf(client, "POST %s?size=1 HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n", httpPath, remoteAddr)
		if err != nil {
			t.Fatal(err)
		}
		response, err := stdhttp.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != stdhttp.StatusOK || response.Close {
			t.Fatalf("expected a successful keepalive response: %s, close=%v", response.Status, response.Close)
		}
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if err := tunnel.Close(); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s connection outlived TestTunnel.Close", scenario)
	}
	var one [1]byte
	if _, err := client.Read(one[:]); err != io.EOF {
		t.Fatalf("%s peer was not closed: %v", scenario, err)
	}
}
