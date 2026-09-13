package openvpn

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClientClosesOnSoftReset(t *testing.T) {
	for _, name := range []string{"plain", "tls-crypt"} {
		t.Run(name, func(t *testing.T) {
			var (
				config      ClientConfig
				serverCrypt *TLSCrypt
				err         error
			)
			switch name {
			case "tls-crypt":
				config.TLSCryptKey = testStaticKey()
				serverCrypt, err = NewTLSCrypt(testStaticKey(), false)
			}
			if err != nil {
				t.Fatal(err)
			}

			clientIO, serverIO := newMemoryPacketPair()
			client, err := NewClient(&config, clientIO)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var serverID SessionID
			copy(serverID[:], []byte("server01"))
			client.control.SetRemoteSessionID(serverID)
			go client.watchControl()
			serverControl := NewControlChannel(serverIO, serverCrypt, serverID)
			serverControl.SetRemoteSessionID(client.control.LocalSessionID())

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := client.control.Send(ctx, PControlV1, []byte("client control")); err != nil {
				t.Fatal(err)
			}
			packet, err := serverControl.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if string(packet.Payload) != "client control" {
				t.Fatalf("unexpected client control payload: %q", packet.Payload)
			}
			if err := serverControl.SendAck(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := serverControl.Send(ctx, PControlV1, nil); err != nil {
				t.Fatal(err)
			}
			if err := serverIO.WritePacket(ctx, []byte{opcodeKeyID(PControlSoftResetV1, 1)}); err != nil {
				t.Fatal(err)
			}
			softReset, err := (ControlPacket{
				Opcode:       PControlSoftResetV1,
				KeyID:        1,
				LocalSession: serverID,
				MessageID:    0,
			}).Encode(serverCrypt, 3, 1714567890)
			if err != nil {
				t.Fatal(err)
			}
			if err := serverIO.WritePacket(ctx, softReset); err != nil {
				t.Fatal(err)
			}
			select {
			case <-client.mux.done:
			case <-ctx.Done():
				t.Fatal("client did not close after soft reset")
			}
			if client.control.recvMessage != 1 {
				t.Fatalf("soft reset changed the old epoch receive sequence: %d", client.control.recvMessage)
			}
			if client.control.PendingMessages() != 0 {
				t.Fatalf("expected server ack to clear client pending messages: %d", client.control.PendingMessages())
			}

			ackCtx, ackCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer ackCancel()
			_, err = serverControl.Read(ackCtx)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected deadline after consuming client ack, got %v", err)
			}
			if serverControl.PendingMessages() != 0 {
				t.Fatalf("expected client to ack ordinary control message: %d", serverControl.PendingMessages())
			}
		})
	}
}

func TestClientControlWatcherIgnoresInvalidPackets(t *testing.T) {
	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	var otherID SessionID
	copy(otherID[:], []byte("server02"))

	encode := func(t *testing.T, keyID uint8, local SessionID) []byte {
		t.Helper()
		packet, err := (ControlPacket{
			Opcode:       PControlSoftResetV1,
			KeyID:        keyID,
			LocalSession: local,
			MessageID:    0,
		}).Encode(nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		return packet
	}

	tests := []struct {
		name   string
		packet []byte
	}{
		{"malformed", []byte{opcodeKeyID(PControlSoftResetV1, 1)}},
		{"initial key id", encode(t, 0, serverID)},
		{"wrong session", encode(t, 1, otherID)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientIO, serverIO := newMemoryPacketPair()
			client, err := NewClient(&ClientConfig{}, clientIO)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.control.SetRemoteSessionID(serverID)
			go client.watchControl()

			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if err := serverIO.WritePacket(ctx, test.packet); err != nil {
				t.Fatal(err)
			}
			select {
			case <-client.mux.done:
				t.Fatal("invalid packet closed client")
			case <-ctx.Done():
			}
			client.control.mu.Lock()
			recvMessage := client.control.recvMessage
			ackPending := len(client.control.ackPending)
			client.control.mu.Unlock()
			if recvMessage != 0 || ackPending != 0 {
				t.Fatalf("invalid packet changed reliable state: recv=%d pending-acks=%d", recvMessage, ackPending)
			}
		})
	}
}
