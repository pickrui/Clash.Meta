package easytier

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	corehost "github.com/easytier/easytier/easytier-go"
	"github.com/easytier/easytier/easytier-go/platform"
)

type offlinePlatform struct{}

var errOffline = errors.New("network disabled in embedded runtime fixture")

func (offlinePlatform) ConnectTCP(context.Context, platform.TCPConnectOptions) (net.Conn, error) {
	return nil, errOffline
}
func (offlinePlatform) BindUDP(ctx context.Context, _ platform.UDPBindOptions) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
}
func (offlinePlatform) ListenTCP(ctx context.Context, _ platform.TCPListenOptions) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
}
func (offlinePlatform) LookupIP(context.Context, platform.DNSQuery) ([]netip.Addr, error) {
	return nil, errOffline
}
func (offlinePlatform) LookupTXT(context.Context, platform.DNSQuery) (string, error) {
	return "", errOffline
}
func (offlinePlatform) LookupSRV(context.Context, platform.DNSQuery) ([]*net.SRV, error) {
	return nil, errOffline
}
func (offlinePlatform) LocalAddrForRemote(context.Context, *net.UDPAddr, platform.SocketContext) (net.Addr, error) {
	return nil, errOffline
}

func TestEmbeddedRuntimeLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	platform := platform.Services{Sockets: offlinePlatform{}, DNS: offlinePlatform{}, Environment: offlinePlatform{}}
	host, err := corehost.New(ctx, corehost.Options{Platform: platform})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := host.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	config, err := (Config{
		NetworkName: "fixture", NetworkSecret: "fixture-only", Hostname: "isolated-node",
		IPv4: "10.144.144.1/24", Peers: []string{"tcp://127.0.0.1:1"}, DisableP2P: new(true),
	}).RenderTOML()
	if err != nil {
		t.Fatal(err)
	}
	config = "ipv4_stun_servers = []\nipv6_stun_servers = []\n" + ApplyRequiredFlags(config)
	instance, err := host.CreateInstanceTOML(ctx, "fixture", "018f4fb1-7a2c-7d1f-9d89-935b0ad7e135", config)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if instance.State() != corehost.StateRunning {
		t.Fatalf("instance state = %v", instance.State())
	}
	info, err := instance.ShowNodeInfo(ctx)
	if err != nil || info.GetHostname() != "isolated-node" {
		t.Fatalf("node info = %v, %v", info, err)
	}
	ip, err := ParseNodeIPv4(info.GetIpv4Addr())
	if err != nil || ip.String() != "10.144.144.1" {
		t.Fatalf("node address = %v, %v", ip, err)
	}
	if err := instance.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := instance.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if err := instance.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if instance.State() != corehost.StateStopped {
		t.Fatalf("closed instance state = %v", instance.State())
	}
}
