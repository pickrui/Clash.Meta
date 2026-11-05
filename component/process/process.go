package process

import (
	"errors"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
)

var (
	ErrInvalidNetwork     = errors.New("invalid network")
	ErrPlatformNotSupport = errors.New("not support on this platform")
	ErrNotFound           = errors.New("process not found")
)

const (
	TCP = "tcp"
	UDP = "udp"
)

func FindProcessName(network string, srcIP netip.Addr, srcPort int) (uint32, string, error) {
	return findProcessName(network, srcIP, srcPort, nil)
}

type PackageNameResolver func(metadata *C.Metadata) (string, error)

// DefaultPackageNameResolver
// never change type traits because it's used in CFMA
var DefaultPackageNameResolver PackageNameResolver

func FindPackageName(metadata *C.Metadata) (string, error) {
	if resolver := DefaultPackageNameResolver; resolver != nil {
		return resolver(metadata)
	}
	return "", ErrPlatformNotSupport
}

type processInspector func(uint32, string)

type Info struct {
	UID  uint32
	PID  uint32
	Path string
}

func FindProcessInfo(network string, srcIP netip.Addr, srcPort int) (Info, error) {
	var info Info
	var err error
	info.UID, info.Path, err = findProcessName(network, srcIP, srcPort, func(pid uint32, _ string) { info.PID = pid })
	return info, err
}

func (info Info) Arguments() []string {
	if info.PID == 0 || info.Path == "" {
		return nil
	}
	return readProcessArguments(info.PID, info.Path)
}
