package mkcp

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSlowReaderBoundsReceiveBuffer(t *testing.T) {
	const budget = 4 * 1024
	c := &Conn{
		cfg: Config{ReadBuffer: budget}, conv: 1, created: time.Now(),
		recvCache:  make(map[uint32]*dataSegment),
		readNotify: make(chan struct{}), writeNotify: make(chan struct{}),
		flushNotify: make(chan struct{}, 1),
	}
	payload := bytes.Repeat([]byte("a"), 1024)
	for i := uint32(0); i < 10000; i++ {
		c.Input([]segment{&dataSegment{conv: 1, number: i, payload: payload}})
	}
	require.LessOrEqual(t, len(c.readBuf), budget)
	require.LessOrEqual(t, len(c.recvCache), int(c.cfg.receivingInFlightSize()))

	// A read must deliver the next cached data and advertise the reopened window,
	// even if the sender has already acknowledged all previous ACKs.
	c.ackList = nil
	c.ackDirty = false
	before := c.recvNext
	got := make([]byte, budget)
	n, err := c.Read(got)
	require.NoError(t, err)
	require.Equal(t, budget, n)
	require.Equal(t, bytes.Repeat([]byte("a"), budget), got)
	require.Greater(t, c.recvNext, before)
	acks := c.flushAcksLocked(c.elapsed())
	require.NotEmpty(t, acks)
	require.Equal(t, c.recvNext, acks[0].(*ackSegment).receivingNext)
}

func TestTransferResumesAfterReceiveBufferFills(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := Config{ReadBuffer: 4 * 1024, WriteBuffer: 8 * 1024, TTI: 10, DownlinkCapacity: 1}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	ln, err := Listen(ctx, pc, cfg)
	require.NoError(t, err)
	defer ln.Close()
	raw, err := net.Dial("udp", ln.Addr().String())
	require.NoError(t, err)
	client, err := Dial(ctx, raw, cfg)
	require.NoError(t, err)
	defer client.terminate()
	require.NoError(t, client.SetDeadline(time.Now().Add(10*time.Second)))
	payload := bytes.Repeat([]byte("abcdefgh"), 32*1024)
	written := make(chan error, 1)
	go func() { _, err := client.Write(payload); written <- err }()
	accepted, err := ln.Accept()
	require.NoError(t, err)
	server := accepted.(*Conn)
	require.NoError(t, server.SetDeadline(time.Now().Add(10*time.Second)))
	require.Eventually(t, func() bool {
		server.mu.Lock()
		defer server.mu.Unlock()
		return len(server.recvCache) >= int(cfg.receivingInFlightSize())
	}, 3*time.Second, time.Millisecond)
	server.mu.Lock()
	buffered := len(server.readBuf)
	server.mu.Unlock()
	require.LessOrEqual(t, buffered, int(cfg.ReadBuffer))
	select {
	case err := <-written:
		t.Fatalf("write finished before the blocked reader resumed: %v", err)
	default:
	}
	got := make([]byte, len(payload))
	_, err = io.ReadFull(server, got)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.NoError(t, <-written)
}
