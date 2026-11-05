package v5

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	atomic2 "github.com/metacubex/mihomo/common/atomic"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/common/xsync"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/tuic/types"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/randv2"
)

type ClientOption struct {
	Uuid                  [16]byte
	Password              string
	UdpRelayMode          types.UdpRelayMode
	MaxUdpRelayPacketSize int
	MaxOpenStreams        int64
}

type clientSession struct {
	conn        *quic.Conn
	openStreams atomic.Int64
	udpInputMap xsync.Map[uint16, net.Conn]
}

type clientImpl struct {
	*ClientOption
	dialFn types.DialFunc
	udp    bool

	session   atomic.Pointer[clientSession]
	connMutex sync.Mutex
	closed    atomic.Bool

	// only ready for PoolClient
	lastVisited atomic2.TypedValue[time.Time]
}

func (t *clientImpl) OpenStreams() int64 {
	if session := t.session.Load(); session != nil {
		return session.openStreams.Load()
	}
	return 0
}

func (t *clientImpl) LastVisited() time.Time {
	return t.lastVisited.Load()
}

func (t *clientImpl) SetLastVisited(last time.Time) {
	t.lastVisited.Store(last)
}

func (t *clientImpl) getSession(ctx context.Context) (*clientSession, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.closed.Load() {
		return nil, types.ClientClosed
	}
	session := t.session.Load()
	if session == nil {
		quicConn, err := t.dialFn(ctx)
		if err != nil {
			return nil, err
		}
		session = &clientSession{conn: quicConn}
		t.session.Store(session)
		go func() { _ = t.sendAuthentication(session) }()
		if t.udp && t.UdpRelayMode == types.QUIC {
			go func() { _ = t.handleUniStream(session) }()
		}
		// TCP sessions also receive v5 heartbeat datagrams.
		go func() { _ = t.handleMessage(session) }()
	}
	if session.openStreams.Add(1) >= t.MaxOpenStreams {
		session.openStreams.Add(-1)
		return nil, types.TooManyOpenStreams
	}
	return session, nil
}

func (t *clientImpl) sendAuthentication(session *clientSession) (err error) {
	quicConn := session.conn
	defer func() {
		t.deferSession(session, err)
	}()
	stream, err := quicConn.OpenUniStream()
	if err != nil {
		return err
	}
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	token, err := GenToken(quicConn.ConnectionState(), t.Uuid, t.Password)
	if err != nil {
		return err
	}
	err = NewAuthenticate(t.Uuid, token).WriteTo(buf)
	if err != nil {
		return err
	}
	_, err = buf.WriteTo(stream)
	if err != nil {
		return err
	}
	err = stream.Close()
	if err != nil {
		return
	}
	return nil
}

func (t *clientImpl) handleUniStream(session *clientSession) (err error) {
	quicConn := session.conn
	defer func() {
		t.deferSession(session, err)
	}()
	for {
		var stream *quic.ReceiveStream
		stream, err = quicConn.AcceptUniStream(context.Background())
		if err != nil {
			return err
		}
		go func() (err error) {
			var assocId uint16
			defer func() {
				t.deferSession(session, err)
				if err != nil && assocId != 0 {
					if val, ok := session.udpInputMap.LoadAndDelete(assocId); ok {
						if conn, ok := val.(net.Conn); ok {
							_ = conn.Close()
						}
					}
				}
				stream.CancelRead(0)
			}()
			reader := bufio.NewReader(stream)
			commandHead, err := ReadCommandHead(reader)
			if err != nil {
				return
			}
			switch commandHead.TYPE {
			case PacketType:
				var packet Packet
				packet, err = ReadPacketWithHead(commandHead, reader)
				if err != nil {
					return
				}
				if t.udp && t.UdpRelayMode == types.QUIC {
					assocId = packet.ASSOC_ID
					if val, ok := session.udpInputMap.Load(assocId); ok {
						if conn, ok := val.(net.Conn); ok {
							writer := bufio.NewWriterSize(conn, packet.BytesLen())
							_ = packet.WriteTo(writer)
							_ = writer.Flush()
						}
					}
				}
			}
			return
		}()
	}
}

func (t *clientImpl) handleMessage(session *clientSession) (err error) {
	quicConn := session.conn
	defer func() {
		t.deferSession(session, err)
	}()
	for {
		var message []byte
		message, err = quicConn.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		go func() (err error) {
			var assocId uint16
			defer func() {
				t.deferSession(session, err)
				if err != nil && assocId != 0 {
					if val, ok := session.udpInputMap.LoadAndDelete(assocId); ok {
						if conn, ok := val.(net.Conn); ok {
							_ = conn.Close()
						}
					}
				}
			}()
			reader := bytes.NewBuffer(message)
			commandHead, err := ReadCommandHead(reader)
			if err != nil {
				return
			}
			switch commandHead.TYPE {
			case PacketType:
				var packet Packet
				packet, err = ReadPacketWithHead(commandHead, reader)
				if err != nil {
					return
				}
				if t.udp && t.UdpRelayMode == types.NATIVE {
					assocId = packet.ASSOC_ID
					if val, ok := session.udpInputMap.Load(assocId); ok {
						if conn, ok := val.(net.Conn); ok {
							_, _ = conn.Write(message)
						}
					}
				}
			case HeartbeatType:
				var heartbeat Heartbeat
				heartbeat, err = ReadHeartbeatWithHead(commandHead, reader)
				if err != nil {
					return
				}
				heartbeat.BytesLen()
			}
			return
		}()
	}
}

func (t *clientImpl) deferSession(session *clientSession, err error) {
	var netError net.Error
	if err != nil && errors.As(err, &netError) {
		t.forceClose(session, err)
	}
}

func (t *clientImpl) forceClose(session *clientSession, err error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if session == nil {
		session = t.session.Load()
	}
	if session == nil {
		return
	}
	t.session.CompareAndSwap(session, nil)
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	_ = session.conn.CloseWithError(ProtocolError, errStr)
	session.udpInputMap.Range(func(key uint16, conn net.Conn) bool {
		_ = conn.Close()
		session.udpInputMap.Delete(key)
		return true
	})
}

func (t *clientImpl) releaseStream(session *clientSession) {
	if session.openStreams.Add(-1) == 0 && t.closed.Load() {
		t.forceClose(session, types.ClientClosed)
	}
}

func (t *clientImpl) Close() {
	t.connMutex.Lock()
	t.closed.Store(true)
	session := t.session.Load()
	idle := session != nil && session.openStreams.Load() == 0
	t.connMutex.Unlock()
	if idle {
		t.forceClose(session, types.ClientClosed)
	}
}

func (t *clientImpl) DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	session, err := t.getSession(ctx)
	if err != nil {
		return nil, err
	}
	quicConn := session.conn
	stream, err := func() (stream net.Conn, err error) {
		defer func() {
			t.deferSession(session, err)
		}()
		buf := pool.GetBuffer()
		defer pool.PutBuffer(buf)
		err = NewConnect(NewAddress(metadata)).WriteTo(buf)
		if err != nil {
			t.releaseStream(session)
			return nil, err
		}
		quicStream, err := quicConn.OpenStream()
		if err != nil {
			t.releaseStream(session)
			return nil, err
		}
		stream = types.NewQuicStreamConn(
			quicStream,
			quicConn.LocalAddr(),
			quicConn.RemoteAddr(),
			func() {
				common.AfterGrace(common.StreamGrace, t, session, (*clientImpl).releaseStream)
			},
		)
		_, err = buf.WriteTo(stream)
		if err != nil {
			_ = stream.Close()
			return nil, err
		}
		return stream, err
	}()
	if err != nil {
		return nil, err
	}

	return stream, nil
}

func (t *clientImpl) ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	session, err := t.getSession(ctx)
	if err != nil {
		return nil, err
	}
	quicConn := session.conn

	pipe1, pipe2 := N.Pipe()
	t.connMutex.Lock()
	if t.session.Load() != session || t.closed.Load() {
		t.connMutex.Unlock()
		_ = pipe1.Close()
		_ = pipe2.Close()
		t.releaseStream(session)
		return nil, types.ClientClosed
	}
	var connId uint16
	for {
		connId = uint16(randv2.IntN(0xFFFF))
		_, loaded := session.udpInputMap.LoadOrStore(connId, pipe1)
		if !loaded {
			break
		}
	}
	t.connMutex.Unlock()
	pc := &quicStreamPacketConn{
		connId:                connId,
		quicConn:              quicConn,
		inputConn:             N.NewBufferedConn(pipe2),
		udpRelayMode:          t.UdpRelayMode,
		maxUdpRelayPacketSize: t.MaxUdpRelayPacketSize,
		deferQuicConnFn:       func(_ *quic.Conn, err error) { t.deferSession(session, err) },
		closeDeferFn: func() {
			session.udpInputMap.Delete(connId)
			common.AfterGrace(common.StreamGrace, t, session, (*clientImpl).releaseStream)
		},
	}
	return pc, nil
}

type Client struct {
	*clientImpl // use an independent pointer to let Finalizer can work no matter somewhere handle an influence in clientImpl inner
}

func (t *Client) DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	conn, err := t.clientImpl.DialContext(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return N.NewRefConn(conn, t), err
}

func (t *Client) ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	pc, err := t.clientImpl.ListenPacket(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return N.NewRefPacketConn(pc, t), nil
}

func (t *Client) forceClose() {
	t.clientImpl.forceClose(nil, types.ClientClosed)
}

func (t *Client) ForceClose() {
	t.closed.Store(true)
	t.forceClose()
}

func NewClient(clientOption *ClientOption, udp bool, dialFn types.DialFunc) *Client {
	ci := &clientImpl{
		ClientOption: clientOption,
		dialFn:       dialFn,
		udp:          udp,
	}
	c := &Client{ci}
	runtime.SetFinalizer(c, closeClient)
	log.Debugln("New TuicV5 Client at %p", c)
	return c
}

func closeClient(client *Client) {
	log.Debugln("Close TuicV5 Client at %p", client)
	client.forceClose()
}
