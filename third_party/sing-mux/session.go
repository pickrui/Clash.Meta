package mux

import (
	"context"
	"io"
	"net"
	"time"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/smux"
	"github.com/metacubex/yamux"
)

type abstractSession interface {
	Open(tcpTimeout time.Duration) (net.Conn, error)
	Accept() (net.Conn, error)
	NumStreams() int
	Close() error
	IsClosed() bool
	CanTakeNewRequest() bool
}

func newClientSession(conn net.Conn, protocol byte) (abstractSession, error) {
	switch protocol {
	case ProtocolH2Mux:
		session, err := newH2MuxClient(conn)
		if err != nil {
			return nil, err
		}
		return session, nil
	case ProtocolSmux:
		client, err := smux.Client(conn, smuxConfig())
		if err != nil {
			return nil, err
		}
		return &smuxSession{client}, nil
	case ProtocolYAMux:
		client, err := yamux.Client(conn, yaMuxConfig(), nil)
		if err != nil {
			return nil, err
		}
		return &yamuxSession{client}, nil
	default:
		return nil, E.New("unexpected protocol ", protocol)
	}
}

func newServerSession(conn net.Conn, protocol byte) (abstractSession, error) {
	switch protocol {
	case ProtocolH2Mux:
		return newH2MuxServer(conn), nil
	case ProtocolSmux:
		client, err := smux.Server(conn, smuxConfig())
		if err != nil {
			return nil, err
		}
		return &smuxSession{client}, nil
	case ProtocolYAMux:
		client, err := yamux.Server(conn, yaMuxConfig(), nil)
		if err != nil {
			return nil, err
		}
		return &yamuxSession{client}, nil
	default:
		return nil, E.New("unexpected protocol ", protocol)
	}
}

var _ abstractSession = (*smuxSession)(nil)

type smuxSession struct {
	*smux.Session
}

func (s *smuxSession) Open(tcpTimeout time.Duration) (net.Conn, error) {
	return s.OpenStream()
}

func (s *smuxSession) Accept() (net.Conn, error) {
	return s.AcceptStream()
}

func (s *smuxSession) CanTakeNewRequest() bool {
	return true
}

type yamuxSession struct {
	*yamux.Session
}

func (s *yamuxSession) Open(tcpTimeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tcpTimeout)
	defer cancel()
	return s.Session.Open(ctx)
}

func (y *yamuxSession) CanTakeNewRequest() bool {
	return true
}

func smuxConfig() *smux.Config {
	config := smux.DefaultConfig()
	config.KeepAliveDisabled = true
	return config
}

func yaMuxConfig() *yamux.Config {
	config := yamux.DefaultConfig()
	config.LogOutput = io.Discard
	//config.StreamCloseTimeout = TCPTimeout
	//config.StreamOpenTimeout = TCPTimeout
	return config
}
