package openvpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"
)

func newWriteTestClient(t *testing.T, packetIO PacketIO) (*Client, *DataChannel) {
	t.Helper()
	client, err := NewClient(&ClientConfig{Cipher: CipherAES128GCM, Auth: AuthSHA256}, packetIO)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	keys := &KeyMaterial{SendCipherKey: bytes.Repeat([]byte{0x11}, 16), SendHMACKey: bytes.Repeat([]byte{0x22}, maxHMACKeyLength), RecvCipherKey: bytes.Repeat([]byte{0x33}, 16), RecvHMACKey: bytes.Repeat([]byte{0x44}, maxHMACKeyLength)}
	client.data, err = NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	client.installDataChannel(client.data)
	peer, err := NewDataChannel(&KeyMaterial{SendCipherKey: keys.RecvCipherKey, SendHMACKey: keys.RecvHMACKey, RecvCipherKey: keys.SendCipherKey, RecvHMACKey: keys.SendHMACKey}, CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	return client, peer
}
func TestClientWritesDataAndPing(t *testing.T) {
	left, right := newMemoryPacketPair()
	defer right.Close()
	client, peer := newWriteTestClient(t, left)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payload := []byte{0x45, 0, 0, 4}
	if err := client.WriteIPPacket(ctx, payload); err != nil {
		t.Fatalf("first data write: %v", err)
	}
	if err := client.WritePing(ctx); err != nil {
		t.Fatalf("ping write: %v", err)
	}
	for _, want := range [][]byte{payload, openVPNPingPacket} {
		packet, err := right.ReadPacket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got, err := peer.Decrypt(packet)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("plaintext=%x, err=%v, want %x", got, err, want)
		}
	}
}
func TestClientSerializesConcurrentWrites(t *testing.T) {
	left, right := newMemoryPacketPair()
	defer right.Close()
	client, peer := newWriteTestClient(t, left)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	const count = 32
	var group sync.WaitGroup
	errorsCh := make(chan error, count)
	for i := 0; i < count; i++ {
		group.Add(1)
		go func(i int) { defer group.Done(); errorsCh <- client.WriteIPPacket(ctx, []byte{0x45, byte(i)}) }(i)
	}
	t.Cleanup(func() { cancel(); group.Wait() })
	seen := make(map[byte]bool)
	for i := 1; i <= count; i++ {
		packet, err := right.ReadPacket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if id := binary.BigEndian.Uint32(packet[4:8]); id != uint32(i) {
			t.Fatalf("packet id=%d, want %d", id, i)
		}
		payload, err := peer.Decrypt(packet)
		if err != nil || len(payload) != 2 || payload[0] != 0x45 || seen[payload[1]] {
			t.Fatalf("corrupted or duplicate packet %x: %v", payload, err)
		}
		seen[payload[1]] = true
	}
	group.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

type failingWritePacketIO struct {
	PacketIO
	fail bool
	err  error
}

func (p *failingWritePacketIO) WritePacket(ctx context.Context, data []byte) error {
	if p.fail {
		p.fail = false
		return p.err
	}
	return p.PacketIO.WritePacket(ctx, data)
}
func TestClientWriteFailureAndCancellationReleasePermit(t *testing.T) {
	left, right := newMemoryPacketPair()
	defer right.Close()
	failure := errors.New("fixture write failed")
	client, peer := newWriteTestClient(t, &failingWritePacketIO{PacketIO: left, fail: true, err: failure})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.WritePing(ctx); !errors.Is(err, failure) {
		t.Fatalf("write error=%v", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err := client.WritePing(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write=%v", err)
	}
	if err := client.WritePing(ctx); err != nil {
		t.Fatalf("write after failure: %v", err)
	}
	packet, err := right.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := peer.Decrypt(packet)
	if err != nil || !IsPingPacket(got) {
		t.Fatalf("ping=%x error=%v", got, err)
	}
}
