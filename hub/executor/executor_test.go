package executor

import (
	"testing"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

func TestTemporaryUpdateGeneralRestoresGlobalFingerprint(t *testing.T) {
	previous := tlsC.GetGlobalFingerprint()
	t.Cleanup(func() { tlsC.SetGlobalFingerprint(previous) })

	tlsC.SetGlobalFingerprint("firefox")
	general := GetGeneral()
	if general.GlobalClientFingerprint != "firefox" {
		t.Fatalf("GetGeneral() fingerprint = %q", general.GlobalClientFingerprint)
	}

	updated := *general
	updated.GlobalClientFingerprint = "chrome"
	rollback := temporaryUpdateGeneral(&updated)
	if got := tlsC.GetGlobalFingerprint(); got != "chrome" {
		t.Fatalf("updated fingerprint = %q", got)
	}
	rollback()
	if got := tlsC.GetGlobalFingerprint(); got != "firefox" {
		t.Fatalf("restored fingerprint = %q", got)
	}
}
