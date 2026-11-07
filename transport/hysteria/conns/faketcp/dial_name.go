package faketcp

import (
	"net"

	"github.com/metacubex/mihomo/component/resolver"
)

// checkDialName runs before net.ResolveTCPAddr, which asks the system DNS directly.
func checkDialName(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil // net.ResolveTCPAddr reports it
	}
	return resolver.CheckName(host)
}
