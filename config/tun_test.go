package config

import (
	"fmt"
	"github.com/metacubex/mihomo/listener/inbound"
	"testing"
)

func TestParseTunKeepsCongestionController(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("tun:\n  stack: mips\n  congestion-controller: bbr\n"))
	if err != nil {
		t.Fatal(err)
	}
	general := &General{}
	if err := parseTun(raw.Tun, &DNS{}, general); err != nil {
		t.Fatal(err)
	}
	if got := general.Tun.CongestionController; got != "bbr" {
		t.Fatalf("congestion controller = %q, want bbr", got)
	}
	// ReCreateTun keeps the running TUN while the options are Equal.
	changed := general.Tun
	changed.CongestionController = "cubic"
	if general.Tun.Equal(changed) {
		t.Fatal("a changed congestion controller left the TUN options equal")
	}
}

func TestTunDNSModes(t *testing.T) {
	for _, mode := range []string{"", "disabled", "native", "hijack", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			raw, err := UnmarshalRawConfig([]byte(fmt.Sprintf("tun:\n  dns-mode: %q\n", mode)))
			if err != nil {
				t.Fatal(err)
			}
			general := &General{}
			err = parseTun(raw.Tun, &DNS{}, general)
			_, inboundErr := inbound.NewTun(&inbound.TunOption{DNSMode: mode})
			if mode == "invalid" {
				if err == nil || inboundErr == nil {
					t.Fatal("invalid mode reached listener setup")
				}
				return
			}
			if err != nil || inboundErr != nil {
				t.Fatalf("parse: %v, inbound: %v", err, inboundErr)
			}
			if general.Tun.DNSMode != mode {
				t.Fatalf("mode lost: %q", general.Tun.DNSMode)
			}
			changed := general.Tun
			changed.DNSMode = "other"
			if general.Tun.Equal(changed) {
				t.Fatal("changed DNS mode would reuse the old listener")
			}
		})
	}
}
