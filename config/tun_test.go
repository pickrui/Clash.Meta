package config

import (
	"fmt"
	"github.com/metacubex/mihomo/listener/inbound"
	"testing"
)

func TestTunProcessorsPerChannel(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        int
	}{
		{"default", "{}", 1},
		{"automatic", "tun:\n  processors-per-channel: 0\n", 0},
		{"explicit", "tun:\n  processors-per-channel: 2\n", 2},
		{"maximum", "tun:\n  processors-per-channel: 256\n", 256},
		{"negative", "tun:\n  processors-per-channel: -1\n", -1},
		{"excessive", "tun:\n  processors-per-channel: 257\n", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := UnmarshalRawConfig([]byte(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			general := &General{}
			err = parseTun(raw.Tun, &DNS{}, general)
			_, inboundErr := inbound.NewTun(&inbound.TunOption{
				ProcessorsPerChannel: raw.Tun.ProcessorsPerChannel,
			})
			if tc.want < 0 {
				if err == nil || inboundErr == nil {
					t.Fatal("unsafe processor count reached listener setup")
				}
				return
			}
			if err != nil || inboundErr != nil {
				t.Fatalf("parse: %v, inbound: %v", err, inboundErr)
			}
			if got := general.Tun.ProcessorsPerChannel; got != tc.want {
				t.Fatalf("processor count = %v, want %d", got, tc.want)
			}
			changed := general.Tun
			changed.ProcessorsPerChannel++
			if general.Tun.Equal(changed) {
				t.Fatal("changed processor count would reuse the old listener")
			}
		})
	}
}

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
