package tfo

import (
	"net"
	"reflect"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

var windowsFDLayoutCompatible = checkWindowsFDLayout()

func checkWindowsFDLayout() bool {
	tcp := reflect.TypeOf(net.TCPConn{})
	if tcp.NumField() != 1 || tcp.Field(0).Offset != 0 {
		return false
	}
	conn := tcp.Field(0).Type
	if conn.Kind() != reflect.Struct || conn.NumField() != 1 || conn.Field(0).Offset != 0 {
		return false
	}
	fd := conn.Field(0).Type
	return fd.Kind() == reflect.Pointer && tcp.Size() == fd.Size() &&
		matchingSocketLayout(reflect.TypeOf(netFD{}), fd.Elem())
}

func matchingSocketLayout(local, actual reflect.Type) bool {
	return matchSocketLayout(local, actual, make(map[[2]reflect.Type]bool))
}

func matchSocketLayout(local, actual reflect.Type, seen map[[2]reflect.Type]bool) bool {
	if local == actual {
		return true
	}
	if local.Kind() != actual.Kind() || local.Size() != actual.Size() || local.Align() != actual.Align() {
		return false
	}
	pair := [2]reflect.Type{local, actual}
	if seen[pair] {
		return true
	}
	seen[pair] = true
	switch local.Kind() {
	case reflect.Struct:
		if local.NumField() != actual.NumField() {
			return false
		}
		for i := 0; i < local.NumField(); i++ {
			a, b := local.Field(i), actual.Field(i)
			if a.Name != b.Name || a.Offset != b.Offset || !matchSocketLayout(a.Type, b.Type, seen) {
				return false
			}
		}
		return true
	case reflect.Pointer, reflect.Slice:
		return matchSocketLayout(local.Elem(), actual.Elem(), seen)
	case reflect.Array:
		return local.Len() == actual.Len() && matchSocketLayout(local.Elem(), actual.Elem(), seen)
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.String:
		return local.Name() == actual.Name()
	default:
		return false
	}
}

// Copied from src/net/tcpsock_posix.go
func sockaddrToTCP(sa syscall.Sockaddr) net.Addr {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		return &net.TCPAddr{IP: sa.Addr[0:], Port: sa.Port}
	case *syscall.SockaddrInet6:
		zone := ""
		if sa.ZoneId != 0 {
			zone = strconv.Itoa(int(sa.ZoneId))
		}
		return &net.TCPAddr{IP: sa.Addr[0:], Port: sa.Port, Zone: zone}
	}
	return nil
}

// Network file descriptor.
//
// Copied from src/net/fd_posix.go
type netFD struct {
	pfd pFD

	// immutable until Close
	family      int
	sotype      int
	isConnected bool // handshake completed or use of association with peer
	net         string
	laddr       net.Addr
	raddr       net.Addr
}

func newFD(sysfd syscall.Handle, family, sotype int, net string) (*netFD, error) {
	ret := &netFD{
		pfd: pFD{
			Sysfd:         sysfd,
			IsStream:      sotype == syscall.SOCK_STREAM,
			ZeroReadIsEOF: sotype != syscall.SOCK_DGRAM && sotype != syscall.SOCK_RAW,
		},
		family: family,
		sotype: sotype,
		net:    net,
	}
	return ret, nil
}

func netFDClose(fd *netFD) error {
	return (*net.TCPConn)(unsafe.Pointer(&fd)).Close()
}

func (fd *netFD) ctrlNetwork() string {
	switch fd.net {
	case "unix", "unixgram", "unixpacket":
		return fd.net
	}
	switch fd.net[len(fd.net)-1] {
	case '4', '6':
		return fd.net
	}
	if fd.family == syscall.AF_INET {
		return fd.net + "4"
	}
	return fd.net + "6"
}

func (fd *netFD) Close() error {
	return (*net.TCPConn)(unsafe.Pointer(&fd)).Close()
}

func (fd *netFD) Write(p []byte) (int, error) {
	return (*net.TCPConn)(unsafe.Pointer(&fd)).Write(p)
}

func (fd *netFD) SetWriteDeadline(t time.Time) error {
	return (*net.TCPConn)(unsafe.Pointer(&fd)).SetWriteDeadline(t)
}

func (fd *netFD) SyscallConn() (syscall.RawConn, error) {
	return (*net.TCPConn)(unsafe.Pointer(&fd)).SyscallConn()
}
