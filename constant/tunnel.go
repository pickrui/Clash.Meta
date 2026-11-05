package constant

import (
	"context"
	"net"
)

type Tunnel interface {
	// HandleTCPConn will handle a tcp connection blocking
	HandleTCPConn(conn net.Conn, metadata *Metadata)
	// HandleUDPPacket will handle a udp packet nonblocking
	HandleUDPPacket(packet UDPPacket, metadata *Metadata)
	// NatTable return nat table
	NatTable() NatTable
}

// RuleDialer dials the way a local app's connection to metadata would go:
// through the proxy the rules pick, which check may refuse before the dial.
type RuleDialer interface {
	DialTCPByRules(ctx context.Context, metadata *Metadata, check func(Proxy, Rule) error) (Conn, error)
}
