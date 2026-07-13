package common

import "testing"

func TestNewSniffProtocolRejectsEmptyPayload(t *testing.T) {
	for _, payload := range []string{"", "  \t"} {
		if _, err := NewSniffProtocol(payload, "REJECT"); err == nil {
			t.Fatalf("NewSniffProtocol(%q) accepted an empty payload", payload)
		}
	}
}

func TestNewSniffProtocolNormalizesPayload(t *testing.T) {
	rule, err := NewSniffProtocol(" STUN ", "REJECT")
	if err != nil {
		t.Fatal(err)
	}
	if rule.Payload() != "stun" {
		t.Fatalf("Payload() = %q", rule.Payload())
	}
}
