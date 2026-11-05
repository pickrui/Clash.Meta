package shadowaead_2022

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/sing-shadowsocks2/cipher"
	M "github.com/metacubex/sing/common/metadata"
)

type earlyResponseConn struct {
	net.Conn
	peer    net.Conn
	method  *Method
	release chan struct{}
}

func (c *earlyResponseConn) Write(request []byte) (int, error) {
	m := c.method
	salt := bytes.Repeat([]byte{0x73}, m.keySaltLength)
	key := SessionKey(m.pskList[len(m.pskList)-1], salt, m.keySaltLength)
	aead, err := m.constructor(key)
	if err != nil {
		return 0, err
	}
	header := []byte{HeaderTypeServer}
	header = binary.BigEndian.AppendUint64(header, uint64(m.time().Unix()))
	header = append(header, request[:m.keySaltLength]...)
	header = binary.BigEndian.AppendUint16(header, 1)
	nonce := make([]byte, aead.NonceSize())
	wire := append(salt, aead.Seal(nil, nonce, header, nil)...)
	nonce[0] = 1
	wire = append(wire, aead.Seal(nil, nonce, []byte("r"), nil)...)
	go func() { _, _ = c.peer.Write(wire) }()
	// The peer may reply before the initial socket Write returns.
	<-c.release
	return len(request), nil
}

func TestEarlyResponseBeforeRequestWriteReturns(t *testing.T) {
	for _, size := range []int{16, 32} {
		name := "2022-blake3-aes-128-gcm"
		if size == 32 {
			name = "2022-blake3-aes-256-gcm"
		}
		t.Run(name, func(t *testing.T) {
			generic, err := NewMethod(name, C.MethodOptions{KeyList: [][]byte{bytes.Repeat([]byte{0x42}, size)}})
			if err != nil {
				t.Fatal(err)
			}
			raw, peer := net.Pipe()
			defer raw.Close()
			defer peer.Close()
			_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
			release := make(chan struct{})
			socket := &earlyResponseConn{Conn: raw, peer: peer, method: generic.(*Method), release: release}
			conn := generic.DialEarlyConn(socket, M.ParseSocksaddr("target.test:443"))
			written := make(chan error, 1)
			go func() { _, err := conn.Write([]byte("request")); written <- err }()
			reply := make([]byte, 1)
			n, err := conn.Read(reply)
			close(release)
			writeErr := <-written
			if err != nil || n != 1 || reply[0] != 'r' {
				t.Fatalf("early reply=%q n=%d err=%v", reply, n, err)
			}
			if writeErr != nil {
				t.Fatal(writeErr)
			}
		})
	}
}
