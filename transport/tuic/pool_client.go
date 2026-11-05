package tuic

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	list "github.com/bahlo/generic-list-go"
	"github.com/metacubex/quic-go"
)

type PoolClient struct {
	newClientOptionV4 *ClientOptionV4
	newClientOptionV5 *ClientOptionV5

	dialFn          DialFunc
	tcpClients      list.List[Client]
	tcpClientsMutex sync.Mutex
	udpClients      list.List[Client]
	udpClientsMutex sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	closeOnce       sync.Once
}

func (t *PoolClient) DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	client, err := t.getClient(false)
	if err != nil {
		return nil, err
	}
	conn, err := client.DialContext(ctx, metadata)
	if errors.Is(err, TooManyOpenStreams) {
		client, err = t.newClient(false)
		if err == nil {
			conn, err = client.DialContext(ctx, metadata)
		}
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefConn(conn, t), err
}

func (t *PoolClient) ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	client, err := t.getClient(true)
	if err != nil {
		return nil, err
	}
	pc, err := client.ListenPacket(ctx, metadata)
	if errors.Is(err, TooManyOpenStreams) {
		client, err = t.newClient(true)
		if err == nil {
			pc, err = client.ListenPacket(ctx, metadata)
		}
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefPacketConn(pc, t), nil
}

func (t *PoolClient) clients(udp bool) (*list.List[Client], *sync.Mutex) {
	if udp {
		return &t.udpClients, &t.udpClientsMutex
	}
	return &t.tcpClients, &t.tcpClientsMutex
}

func (t *PoolClient) newClient(udp bool) (Client, error) {
	clients, clientsMutex := t.clients(udp)
	clientsMutex.Lock()
	defer clientsMutex.Unlock()
	if t.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	return t.newClientLocked(clients, udp), nil
}

func (t *PoolClient) newClientLocked(clients *list.List[Client], udp bool) (client Client) {
	if t.newClientOptionV4 != nil {
		client = NewClientV4(t.newClientOptionV4, udp, t.dialFn)
	} else {
		client = NewClientV5(t.newClientOptionV5, udp, t.dialFn)
	}

	client.SetLastVisited(time.Now())

	clients.PushFront(client)
	return client
}

func (t *PoolClient) getClient(udp bool) (Client, error) {
	clients, clientsMutex := t.clients(udp)
	clientsMutex.Lock()
	defer clientsMutex.Unlock()
	if t.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	var bestClient Client

	for it := clients.Front(); it != nil; {
		client := it.Value
		if client == nil {
			next := it.Next()
			clients.Remove(it)
			it = next
			continue
		}
		if bestClient == nil || client.OpenStreams() < bestClient.OpenStreams() {
			bestClient = client
		}
		it = it.Next()
	}
	now := time.Now()
	for it := clients.Front(); it != nil; {
		client := it.Value
		if client != bestClient && client.OpenStreams() == 0 && now.Sub(client.LastVisited()) > 30*time.Minute {
			client.Close()
			next := it.Next()
			clients.Remove(it)
			it = next
			continue
		}
		it = it.Next()
	}

	if bestClient == nil {
		return t.newClientLocked(clients, udp), nil
	}
	bestClient.SetLastVisited(now)
	return bestClient, nil
}

func (t *PoolClient) Close() {
	t.closeOnce.Do(func() {
		// Dialing holds the client connection lock that ForceClose needs.
		t.cancel()
		for _, udp := range []bool{false, true} {
			clients, clientsMutex := t.clients(udp)
			clientsMutex.Lock()
			for it := clients.Front(); it != nil; it = it.Next() {
				it.Value.ForceClose()
			}
			clients.Init()
			clientsMutex.Unlock()
		}
	})
}

func newPoolClient(dialFn DialFunc) *PoolClient {
	poolCtx, cancel := context.WithCancel(context.Background())
	return &PoolClient{
		ctx: poolCtx, cancel: cancel,
		dialFn: func(ctx context.Context) (*quic.Conn, error) {
			if poolCtx.Err() != nil {
				return nil, net.ErrClosed
			}
			ctx, cancel := context.WithCancel(ctx)
			stop := context.AfterFunc(poolCtx, cancel)
			defer func() { stop(); cancel() }()
			conn, err := dialFn(ctx)
			if err != nil {
				return nil, err
			}
			if err = poolCtx.Err(); err != nil {
				_ = conn.CloseWithError(0, err.Error())
				return nil, err
			}
			return conn, nil
		},
	}
}

func NewPoolClientV4(clientOption *ClientOptionV4, dialFn DialFunc) *PoolClient {
	p := newPoolClient(dialFn)
	newClientOption := *clientOption
	p.newClientOptionV4 = &newClientOption
	return p
}

func NewPoolClientV5(clientOption *ClientOptionV5, dialFn DialFunc) *PoolClient {
	p := newPoolClient(dialFn)
	newClientOption := *clientOption
	p.newClientOptionV5 = &newClientOption
	return p
}
