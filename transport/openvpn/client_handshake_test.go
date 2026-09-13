package openvpn

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/metacubex/tls"
)

// Exercise the real client handshake; no test starts the control watcher itself.
func TestHandshakeFailedRekeyUnblocksDataRead(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("tlsCrypt=%t", encrypted), func(t *testing.T) {
			client, server, serverIO := handshakeTestClient(t, encrypted)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			blockedRead := make(chan error, 1)
			go func() { _, err := client.ReadIPPacket(ctx); blockedRead <- err }()
			reset, err := (ControlPacket{Opcode: PControlSoftResetV1, KeyID: 1, LocalSession: server.local, MessageID: 0}).Encode(server.crypt, 100, uint32(time.Now().Unix()))
			if err != nil {
				t.Fatal(err)
			}
			if err := serverIO.WritePacket(ctx, reset); err != nil {
				t.Fatal(err)
			}
			if err := <-blockedRead; !errors.Is(err, net.ErrClosed) {
				t.Fatalf("data read after server reset = %v, want closed link", err)
			}
		})
	}
}

func TestHandshakeClearsDeadlinesAndAcknowledgesControl(t *testing.T) {
	client, server, _ := handshakeTestClient(t, false)
	client.control.mu.Lock()
	readDeadline, writeDeadline := client.control.readDeadline, client.control.writeDeadline
	client.control.mu.Unlock()
	if !readDeadline.IsZero() || !writeDeadline.IsZero() {
		t.Fatalf("handshake deadlines retained: read=%v write=%v", readDeadline, writeDeadline)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := server.Send(ctx, PControlV1, nil); err != nil {
		t.Fatal(err)
	}
	// Read consumes acknowledgements internally and returns only on timeout.
	if _, err := server.Read(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("control read = %v", err)
	}
	if server.PendingMessages() != 0 {
		t.Fatalf("post-handshake control not acknowledged: %d pending", server.PendingMessages())
	}
	select {
	case <-client.mux.done:
		t.Fatal("client closed after successful handshake context was cancelled")
	default:
	}
}

type handshakePeerInfo struct {
	values map[string]string
	want   string
}

func TestHandshakeSendsPeerInfo(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("tlsCrypt=%t", encrypted), func(t *testing.T) {
			handshakeTestClient(t, encrypted, handshakePeerInfo{
				values: map[string]string{"IV_VER": "custom-client/1", "IV_PROTO": "999", "IV_CIPHERS": "wrong", "UV_DEVICE_ID": "id=001", "IV_HWADDR": "52:54:00:ff:72:87"},
				want:   "IV_VER=custom-client/1\nIV_PROTO=22\nIV_CIPHERS=AES-128-GCM\nIV_HWADDR=52:54:00:ff:72:87\nUV_DEVICE_ID=id=001\n",
			})
		})
	}
}

func handshakeTestClient(t *testing.T, encrypted bool, peerInfo ...handshakePeerInfo) (*Client, *ControlChannel, *memoryPacketIO) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"openvpn.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	config := &ClientConfig{CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Proto: ProtoTCP, Cipher: CipherAES128GCM, Auth: "SHA256"}
	if len(peerInfo) > 0 {
		config.PeerInfo = peerInfo[0].values
	}
	var crypt ControlCryptor
	if encrypted {
		config.TLSCryptKey = testStaticKey()
		crypt, err = NewTLSCrypt(testStaticKey(), false)
		if err != nil {
			t.Fatal(err)
		}
	}
	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(config, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = serverIO.Close() })
	var serverID SessionID
	copy(serverID[:], "server01")
	server := NewControlChannel(serverIO, crypt, serverID)
	server.SetRemoteSessionID(client.control.LocalSessionID())
	client.rekeyHandshakeTimeout = 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- func() error {
			packet, err := server.Read(ctx)
			if err != nil {
				return err
			}
			if packet.Opcode != PControlHardResetClientV2 {
				return fmt.Errorf("unexpected reset: %v", packet.Opcode)
			}
			if _, err := server.Send(ctx, PControlHardResetServerV2, nil); err != nil {
				return err
			}
			conn := tls.Server(NewControlConn(server), &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}, MaxVersion: tls.VersionTLS12})
			deadline, _ := ctx.Deadline()
			_ = conn.SetDeadline(deadline)
			if err := conn.HandshakeContext(ctx); err != nil {
				return err
			}
			// Consume key method 2 header and the four length-prefixed strings.
			header := make([]byte, 4+1+keySourcePreMasterSize+2*keySourceRandomSize)
			if _, err := io.ReadFull(conn, header); err != nil {
				return err
			}
			if header[4] != KeyMethod2 {
				return fmt.Errorf("unexpected key method: %d", header[4])
			}
			for index := range 4 {
				var size [2]byte
				if _, err := io.ReadFull(conn, size[:]); err != nil {
					return err
				}
				value := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(conn, value); err != nil {
					return err
				}
				if index == 3 && len(peerInfo) > 0 && string(value) != peerInfo[0].want+"\x00" {
					return fmt.Errorf("unexpected peer-info on the control channel: %q", value)
				}
			}
			response := []byte{0, 0, 0, 0, KeyMethod2}
			response = append(response, bytes.Repeat([]byte{1}, keySourceRandomSize)...)
			response = append(response, bytes.Repeat([]byte{2}, keySourceRandomSize)...)
			response = appendOpenVPNString(response, "server-options")
			for range 3 {
				response = appendOpenVPNString(response, "")
			}
			if _, err := conn.Write(response); err != nil {
				return err
			}
			request := make([]byte, len(PushRequest)+1)
			if _, err := io.ReadFull(conn, request); err != nil {
				return err
			}
			if string(request) != PushRequest+"\x00" {
				return fmt.Errorf("unexpected push request: %q", request)
			}
			if _, err := conn.Write([]byte("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,peer-id 7\x00")); err != nil {
				return err
			}
			return conn.SetDeadline(time.Time{})
		}()
	}()
	push, handshakeErr := client.Handshake(ctx)
	if handshakeErr != nil {
		_ = serverIO.Close()
	}
	if err := <-result; err != nil {
		t.Fatalf("test server handshake: %v (client: %v)", err, handshakeErr)
	}
	if handshakeErr != nil {
		t.Fatal(handshakeErr)
	}
	if push.PeerID != 7 {
		t.Fatalf("unexpected peer id: %d", push.PeerID)
	}
	return client, server, serverIO
}
