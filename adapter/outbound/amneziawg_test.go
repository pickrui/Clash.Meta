//go:build with_gvisor

package outbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	amnezia "github.com/metacubex/amneziawg-go/device_v1"
	M "github.com/metacubex/sing/common/metadata"
)

// Configure the production userspace adapter without starting its TUN or bind.
// No operating-system interface, endpoint connection or handshake is created.
func newAmneziaPacketDevice(t *testing.T) *amnezia.Device {
	t.Helper()
	w, err := NewWireGuard(WireGuardOption{
		Name: "packet-test", Ip: "10.0.0.1", Workers: 1,
		PrivateKey:          base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		WireGuardPeerOption: WireGuardPeerOption{Server: "127.0.0.1", Port: 51820, PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))},
		AmneziaWGOption:     &AmneziaWGOption{S1: 8, S2: 16, S3: 24, S4: 64, H1: "101", H2: "102", H3: "103", H4: "104"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	w.serverAddrMap = make(map[M.Socksaddr]netip.AddrPort)
	config, err := w.genIpcConf(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.device.IpcSet(config); err != nil {
		t.Fatal(err)
	}
	device, ok := w.device.(*amnezia.Device)
	if !ok {
		t.Fatalf("adapter created %T, want AmneziaWG", w.device)
	}
	return device
}

func TestAmneziaWGS4RejectsShortPackets(t *testing.T) {
	device := newAmneziaPacketDevice(t)
	for _, size := range []int{0, 1, 3, 4, 31, 32, 63, 64, 65, 66, 67} {
		for _, clipped := range []bool{true, false} {
			t.Run(fmt.Sprintf("size=%d/clipped=%t", size, clipped), func(t *testing.T) {
				defer func() {
					if value := recover(); value != nil {
						t.Errorf("short packet panicked: %v", value)
					}
				}()
				var buffer [amnezia.MaxMessageSize]byte
				// A reused receive buffer can retain a transport header from an earlier
				// packet. Its bytes beyond the current datagram must never be read.
				binary.LittleEndian.PutUint32(buffer[64:], 104)
				packet := buffer[:size]
				if clipped {
					packet = packet[:size:size]
				}
				if kind, err := device.ProcessAWGPacket(size, &packet, &buffer); err == nil || kind != 0 {
					t.Fatalf("short packet accepted: type=%d err=%v", kind, err)
				}
				if len(packet) != size {
					t.Fatal("rejected packet length changed")
				}
			})
		}
	}
}

func TestAmneziaWGParsesPaddedPackets(t *testing.T) {
	device := newAmneziaPacketDevice(t)
	for _, tc := range []struct {
		name          string
		kind          uint32
		padding, size int
	}{
		{"initiation", 101, 8, amnezia.MessageInitiationSize},
		{"response", 102, 16, amnezia.MessageResponseSize},
		{"cookie", 103, 24, amnezia.MessageCookieReplySize},
		{"keepalive", 104, 64, amnezia.MessageKeepaliveSize},
		{"transport", 104, 64, 128},
		// A transport packet can have the same wire size as a padded initiation.
		{"transport-size-collision", 104, 64, amnezia.MessageInitiationSize + 8 - 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buffer [amnezia.MaxMessageSize]byte
			packet := buffer[:tc.padding+tc.size]
			for i := range packet {
				packet[i] = 0xa5
			}
			binary.LittleEndian.PutUint32(packet[tc.padding:], tc.kind)
			if tc.name == "transport-size-collision" {
				binary.LittleEndian.PutUint32(packet[8:], tc.kind)
			}
			expected := bytes.Clone(packet[tc.padding:])
			kind, err := device.ProcessAWGPacket(len(packet), &packet, &buffer)
			if err != nil {
				t.Fatal(err)
			}
			if kind != tc.kind || !bytes.Equal(packet, expected) {
				t.Fatalf("padded packet changed: type=%d len=%d, want type=%d len=%d", kind, len(packet), tc.kind, len(expected))
			}
		})
	}
}
