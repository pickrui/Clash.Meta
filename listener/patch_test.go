package listener_test

import (
	"net"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/listener"
)

func freePort(t *testing.T) int {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	return probe.Addr().(*net.TCPAddr).Port
}

func TestStopListenerSerializesWithRecreate(t *testing.T) {
	httpPort, socksPort, mixedPort := freePort(t), freePort(t), freePort(t)
	t.Cleanup(listener.StopListener)
	var group sync.WaitGroup
	for range 20 {
		group.Go(func() {
			listener.ReCreateHTTP(httpPort, nil)
			listener.ReCreateSocks(socksPort, nil)
			listener.ReCreateMixed(mixedPort, nil)
		})
		group.Go(listener.StopListener)
	}
	group.Wait()
	listener.StopListener()
	if ports := listener.GetPorts(); ports.Port != 0 || ports.SocksPort != 0 || ports.MixedPort != 0 {
		t.Fatalf("listeners survived StopListener: %+v", ports)
	}
}
