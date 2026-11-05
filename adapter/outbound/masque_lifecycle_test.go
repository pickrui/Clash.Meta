package outbound

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/stretchr/testify/require"
)

func masqueTestOption(t testing.TB) MasqueOption {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	private, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return MasqueOption{
		Name: "masque-test", Server: "127.0.0.1", Port: 443, Ip: "10.0.0.2/32",
		PrivateKey: base64.StdEncoding.EncodeToString(private),
		PublicKey:  base64.StdEncoding.EncodeToString(public),
	}
}

func masqueTestStackModes() []string {
	modes := []string{ipStackAuto, ipStackMips}
	if features.WithGVisor {
		modes = append(modes, ipStackGVisor)
	}
	return modes
}

func TestMasqueUnusedAndCanceledNodesKeepNoStack(t *testing.T) {
	base := masqueTestOption(t)
	for _, mode := range masqueTestStackModes() {
		for _, addresses := range []struct{ name, ip, ipv6 string }{
			{"ipv4", "10.0.0.2/32", ""},
			{"ipv6", "", "fd00::2/128"},
			{"dual-stack", "10.0.0.2/24", "fd00::2/64"},
		} {
			t.Run(mode+"/"+addresses.name, func(t *testing.T) {
				option := base
				option.IPStack.Mode = mode
				option.Ip, option.Ipv6 = addresses.ip, addresses.ipv6
				node, err := NewMasque(option)
				require.NoError(t, err)
				t.Cleanup(func() { _ = node.Close() })
				require.Nil(t, node.tunDevice)
				metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 80}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				_, err = node.DialContext(ctx, metadata)
				require.ErrorIs(t, err, context.Canceled)
				require.Nil(t, node.tunDevice)
				require.NoError(t, node.Close())
				_, err = node.DialContext(context.Background(), metadata)
				require.ErrorIs(t, err, context.Canceled)
				_, err = node.ListenPacketContext(context.Background(), metadata)
				require.ErrorIs(t, err, context.Canceled)
				require.Nil(t, node.tunDevice)
			})
		}
	}
}

func TestMasqueConcurrentFirstDialsReuseStackAfterHandshakeFailure(t *testing.T) {
	option := masqueTestOption(t)
	for _, mode := range masqueTestStackModes() {
		t.Run(mode, func(t *testing.T) {
			option.IPStack.Mode = mode
			node, err := NewMasque(option)
			require.NoError(t, err)
			t.Cleanup(func() { _ = node.Close() })
			handshakeError := errors.New("fixture handshake failure")
			node.h2Transport = &http.Transport{
				DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, handshakeError },
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var workers sync.WaitGroup
			for i := 0; i < 16; i++ {
				workers.Go(func() {
					metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 80}
					_, err := node.DialContext(ctx, metadata)
					if !errors.Is(err, handshakeError) {
						t.Errorf("first dial: %v", err)
					}
				})
			}
			workers.Wait()
			require.NotNil(t, node.tunDevice)
			require.True(t, node.runDevice)
			device := node.tunDevice
			require.ErrorIs(t, node.run(ctx), handshakeError)
			require.Same(t, device, node.tunDevice)
			require.NoError(t, node.Close())
			require.ErrorIs(t, node.run(ctx), context.Canceled)
		})
	}
}

type masqueBlockingStack struct {
	ipStack
	started chan struct{}
	release chan struct{}
	active  atomic.Bool
	overlap atomic.Bool
	closed  atomic.Int32
}

func (s *masqueBlockingStack) Start() error {
	s.active.Store(true)
	close(s.started)
	<-s.release
	s.active.Store(false)
	return nil
}

func (s *masqueBlockingStack) Close() error {
	if s.active.Load() {
		s.overlap.Store(true)
	}
	s.closed.Add(1)
	return nil
}

func TestMasqueCloseSerializesWithDeviceStart(t *testing.T) {
	node, err := NewMasque(masqueTestOption(t))
	require.NoError(t, err)
	device := &masqueBlockingStack{started: make(chan struct{}), release: make(chan struct{})}
	node.tunDevice = device
	started := make(chan error, 1)
	go func() { started <- node.startDevice(context.Background()) }()
	<-device.started
	closed := make(chan error, 1)
	go func() { closed <- node.Close() }()
	<-node.runCtx.Done()
	close(device.release)
	require.NoError(t, <-started)
	require.NoError(t, <-closed)
	require.NoError(t, node.Close())
	require.False(t, device.overlap.Load())
	require.EqualValues(t, 1, device.closed.Load())
}

func TestMasqueStackValidationMatchesBackend(t *testing.T) {
	// gVisor retains workers on constructor errors; keep invalid-input checks
	// in a child process so they cannot starve later transport tests.
	const child = "MIHOMO_MASQUE_VALIDATION_CHILD"
	if os.Getenv(child) != "1" {
		executable, err := os.Executable()
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, executable, "-test.run=^TestMasqueStackValidationMatchesBackend$", "-test.timeout=25s")
		command.Env = append(os.Environ(), child+"=1")
		output, err := command.CombinedOutput()
		require.NoError(t, err, "%s", output)
		return
	}
	base := masqueTestOption(t)
	cases := []struct {
		ip, ipv6 string
		mtu      int
	}{
		{"10.0.0.2/32", "", 0},
		{"10.0.0.2/24", "fd00::2/64", 1280},
		{"10.0.0.2/32", "", 67},
		{"10.0.0.2/32", "", 65536},
		{"10.0.0.2/32", "fd00::2/128", 1000},
		{"10.0.0.255/24", "", 1280},
		{"255.255.255.255/32", "", 1280},
		{"0.0.0.0/32", "", 1280},
		{"224.0.0.1/32", "", 1280},
		{"::/128", "", 1280},
		{"ff02::1/128", "", 1280},
		{"10.0.0.2/32", "10.0.0.2/24", 1280},
		{"::ffff:10.0.0.2/80", "", 1280},
		{"10.0.0.1/24", "::ffff:10.0.0.255/128", 1280},
		{"127.0.0.1/24", "127.0.0.255/32", 1280},
	}
	for _, mode := range masqueTestStackModes() {
		for _, tc := range cases {
			option := base
			option.IPStack.Mode = mode
			option.Ip, option.Ipv6, option.MTU = tc.ip, tc.ipv6, tc.mtu
			prefixes, err := option.Prefixes()
			require.NoError(t, err)
			mtu := option.MTU
			if mtu == 0 {
				mtu = 1280
			}
			stack, backendErr := newIPStack(option.IPStack, prefixes, uint32(mtu))
			if backendErr == nil {
				require.NoError(t, stack.Close())
			}
			node, err := NewMasque(option)
			if node != nil {
				require.NoError(t, node.Close())
			}
			if backendErr != nil {
				require.EqualError(t, err, "create device: "+backendErr.Error(), "%s %+v", mode, tc)
			} else {
				require.NoError(t, err, "%s %+v", mode, tc)
			}
		}
	}
}

func BenchmarkMasqueUnused(b *testing.B) {
	option := masqueTestOption(b)
	for _, mode := range masqueTestStackModes() {
		option.IPStack.Mode = mode
		b.Run(mode, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				node, err := NewMasque(option)
				if err != nil {
					b.Fatal(err)
				}
				if err := node.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
