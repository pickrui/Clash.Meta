package snell

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/metacubex/blake3"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
	"github.com/metacubex/mihomo/transport/socks5"
)

const (
	Version1            = 1
	Version2            = 2
	Version3            = 3
	Version4            = 4
	DefaultSnellVersion = Version1

	// max packet length
	maxLength = 0x3FFF
)

const (
	CommandPing       byte = 0
	CommandConnect    byte = 1
	CommandConnectV2  byte = 5
	CommandUDP        byte = 6
	CommondUDPForward byte = 1

	CommandTunnel byte = 0
	CommandPong   byte = 1
	CommandError  byte = 2

	Version byte = 1
)

const (
	IdentityHeaderLength = 16
	identityWireMagic    = "DLSNID01"
)

var endSignal = []byte{}

type Snell struct {
	net.Conn
	buffer [1]byte
	reply  bool
}

func (s *Snell) Read(b []byte) (int, error) {
	if !s.reply {
		if err := s.readTunnelReply(); err != nil {
			return 0, err
		}
	}
	return s.Conn.Read(b)
}

func (s *Snell) readTunnelReply() error {
	if s.reply {
		return nil
	}
	s.reply = true
	if _, err := io.ReadFull(s.Conn, s.buffer[:]); err != nil {
		return err
	}

	if s.buffer[0] == CommandTunnel {
		return nil
	} else if s.buffer[0] != CommandError {
		return errors.New("command not support")
	}

	// CommandError
	// 1 byte error code
	if _, err := io.ReadFull(s.Conn, s.buffer[:]); err != nil {
		return err
	}
	errcode := int(s.buffer[0])

	// 1 byte error message length
	if _, err := io.ReadFull(s.Conn, s.buffer[:]); err != nil {
		return err
	}
	length := int(s.buffer[0])
	msg := make([]byte, length)

	if _, err := io.ReadFull(s.Conn, msg); err != nil {
		return err
	}

	return fmt.Errorf("server reported code: %d, message: %s", errcode, string(msg))
}

func ReadTunnelReply(conn net.Conn) error {
	snellConn, ok := conn.(*Snell)
	if !ok {
		return nil
	}
	return snellConn.readTunnelReply()
}

func WriteHeader(conn net.Conn, host string, port uint, version int, reuse bool) error {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	buf.WriteByte(Version)
	if version == Version2 || (version == Version4 && reuse) {
		buf.WriteByte(CommandConnectV2)
	} else {
		buf.WriteByte(CommandConnect)
	}

	// clientID length & id
	buf.WriteByte(0)

	// host & port
	buf.WriteByte(uint8(len(host)))
	buf.WriteString(host)
	binary.Write(buf, binary.BigEndian, uint16(port))

	if _, err := conn.Write(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

func WriteUDPHeader(conn net.Conn, version int) error {
	if version < Version3 {
		return errors.New("unsupport UDP version")
	}

	// version, command, clientID length
	_, err := conn.Write([]byte{Version, CommandUDP, 0x00})
	return err
}

func HalfClose(conn net.Conn) error {
	if _, err := conn.Write(endSignal); err != nil {
		return err
	}

	if s, ok := conn.(*Snell); ok {
		s.reply = false
	}
	return nil
}

func IdentityHeaderFromPSK(psk []byte) []byte {
	hash := blake3.Sum512(psk)
	return append([]byte(nil), hash[:IdentityHeaderLength]...)
}

func StreamConnWithIdentity(conn net.Conn, psk []byte, version int) *Snell {
	return streamConn(conn, psk, version, IdentityHeaderFromPSK(psk))
}

func StreamConn(conn net.Conn, psk []byte, version int) *Snell {
	return streamConn(conn, psk, version, nil)
}

func streamConn(conn net.Conn, psk []byte, version int, identity []byte) *Snell {
	var cipher shadowaead.Cipher
	if version != Version1 {
		cipher = NewAES128GCM(psk)
	} else {
		cipher = NewChacha20Poly1305(psk)
	}
	if version == Version4 {
		return &Snell{Conn: newV4Conn(conn, cipher, identity)}
	}
	return &Snell{Conn: shadowaead.NewConn(conn, cipher)}
}

func PacketConn(conn net.Conn) net.PacketConn {
	return &packetConn{
		Conn: conn,
	}
}

func writePacket(w io.Writer, socks5Addr, payload []byte) (int, error) {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	// compose snell UDP address format (refer: icpz/snell-server-reversed)
	// a brand new wheel to replace socks5 address format, well done Yachen
	buf.WriteByte(CommondUDPForward)
	switch socks5Addr[0] {
	case socks5.AtypDomainName:
		hostLen := socks5Addr[1]
		buf.Write(socks5Addr[1 : 1+1+hostLen+2])
	case socks5.AtypIPv4:
		buf.Write([]byte{0x00, 0x04})
		buf.Write(socks5Addr[1 : 1+net.IPv4len+2])
	case socks5.AtypIPv6:
		buf.Write([]byte{0x00, 0x06})
		buf.Write(socks5Addr[1 : 1+net.IPv6len+2])
	}

	buf.Write(payload)
	_, err := w.Write(buf.Bytes())
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

func WritePacket(w io.Writer, socks5Addr, payload []byte) (int, error) {
	if len(payload) <= maxLength {
		return writePacket(w, socks5Addr, payload)
	}

	offset := 0
	total := len(payload)
	for {
		cursor := offset + maxLength
		if cursor > total {
			cursor = total
		}

		n, err := writePacket(w, socks5Addr, payload[offset:cursor])
		if err != nil {
			return offset + n, err
		}

		offset = cursor
		if offset == total {
			break
		}
	}

	return total, nil
}

func ReadPacket(r io.Reader, payload []byte) (net.Addr, int, error) {
	buf := pool.Get(pool.UDPBufferSize)
	defer pool.Put(buf)

	n, err := r.Read(buf)
	headLen := 1
	if err != nil {
		return nil, 0, err
	}
	if n < headLen {
		return nil, 0, errors.New("insufficient UDP length")
	}

	// parse snell UDP response address format
	switch buf[0] {
	case 0x04:
		headLen += net.IPv4len + 2
		if n < headLen {
			err = errors.New("insufficient UDP length")
			break
		}
		buf[0] = socks5.AtypIPv4
	case 0x06:
		headLen += net.IPv6len + 2
		if n < headLen {
			err = errors.New("insufficient UDP length")
			break
		}
		buf[0] = socks5.AtypIPv6
	default:
		err = errors.New("ip version invalid")
	}

	if err != nil {
		return nil, 0, err
	}

	addr := socks5.SplitAddr(buf[0:])
	if addr == nil {
		return nil, 0, errors.New("remote address invalid")
	}
	uAddr := addr.UDPAddr()
	if uAddr == nil {
		return nil, 0, errors.New("parse addr error")
	}

	length := len(payload)
	if n-headLen < length {
		length = n - headLen
	}
	copy(payload[:], buf[headLen:headLen+length])

	return uAddr, length, nil
}

type packetConn struct {
	net.Conn
	rMux sync.Mutex
	wMux sync.Mutex
}

func (pc *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	pc.wMux.Lock()
	defer pc.wMux.Unlock()

	return WritePacket(pc, socks5.ParseAddrToSocksAddr(addr), b)
}

func (pc *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	pc.rMux.Lock()
	defer pc.rMux.Unlock()

	addr, n, err := ReadPacket(pc.Conn, b)
	if err != nil {
		return 0, nil, err
	}

	return n, addr, nil
}
