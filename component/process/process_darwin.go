package process

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	procpidpathinfo     = 0xb
	procpidpathinfosize = 1024
	proccallnumpidinfo  = 0x2
)

var structSize = func() int {
	value, _ := syscall.Sysctl("kern.osrelease")
	major, _, _ := strings.Cut(value, ".")
	n, _ := strconv.ParseInt(major, 10, 64)
	switch true {
	case n >= 22:
		return 408
	default:
		// from darwin-xnu/bsd/netinet/in_pcblist.c:get_pcblist_n
		// size/offset are round up (aligned) to 8 bytes in darwin
		// rup8(sizeof(xinpcb_n)) + rup8(sizeof(xsocket_n)) +
		// 2 * rup8(sizeof(xsockbuf_n)) + rup8(sizeof(xsockstat_n))
		return 384
	}
}()

func findProcessName(network string, ip netip.Addr, port int, inspect processInspector) (uint32, string, error) {
	var spath string
	switch network {
	case TCP:
		spath = "net.inet.tcp.pcblist_n"
	case UDP:
		spath = "net.inet.udp.pcblist_n"
	default:
		return 0, "", ErrInvalidNetwork
	}

	value, err := unix.SysctlRaw(spath)
	if err != nil {
		return 0, "", err
	}
	pid, err := findDarwinSocketOwner(value, network, ip, uint16(port))
	if err != nil {
		return 0, "", err
	}
	path, err := getExecPathFromPID(pid)
	if err == nil && inspect != nil {
		inspect(pid, path)
	}
	return 0, path, err
}

func findDarwinSocketOwner(buf []byte, network string, ip netip.Addr, port uint16) (uint32, error) {
	ip = ip.Unmap()
	itemSize := structSize
	if network == TCP {
		itemSize += 208
	}
	selected, err := selectSocketOwner(network, ip, port, func(yield func(socketOwner) bool) {
		// Skip xinpgen; xinpcb_n and xsocket_n are aligned to eight bytes.
		for i := 24; i+itemSize <= len(buf); i += itemSize {
			inp, so := i, i+104
			srcPort := binary.BigEndian.Uint16(buf[inp+18 : inp+20])
			if srcPort != port {
				continue
			}
			flag := buf[inp+44]
			var srcIP netip.Addr
			switch {
			case flag&0x1 > 0 && ip.Is4():
				srcIP, _ = netip.AddrFromSlice(buf[inp+76 : inp+80])
			case flag&0x2 > 0 && ip.Is6():
				srcIP, _ = netip.AddrFromSlice(buf[inp+64 : inp+80])
			default:
				continue
			}
			if !yield(socketOwner{address: srcIP, port: srcPort, pid: readNativeUint32(buf[so+68 : so+72])}) {
				return
			}
		}
	})
	return selected.pid, err
}

func getExecPathFromPID(pid uint32) (string, error) {
	buf := make([]byte, procpidpathinfosize)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		proccallnumpidinfo,
		uintptr(pid),
		procpidpathinfo,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		procpidpathinfosize)
	if errno != 0 {
		return "", errno
	}

	return unix.ByteSliceToString(buf), nil
}

func readNativeUint32(b []byte) uint32 {
	return *(*uint32)(unsafe.Pointer(&b[0]))
}
