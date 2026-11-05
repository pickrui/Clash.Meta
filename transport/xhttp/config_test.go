package xhttp

import (
	"testing"

	"github.com/metacubex/http"
)

func TestUplinkChunkSizeDefaults(t *testing.T) {
	for _, placement := range []string{PlacementHeader, PlacementCookie, PlacementBody} {
		for _, value := range []string{"", "  ", "0"} {
			config := &Config{UplinkDataPlacement: placement, UplinkChunkSize: value, ScMaxEachPostBytes: "4000-5000"}
			got, err := config.GetNormalizedUplinkChunkSize()
			want := Range{4000, 5000}
			if placement == PlacementHeader {
				want = Range{3 * 1024, 4 * 1024}
			}
			if placement == PlacementCookie {
				want = Range{2 * 1024, 3 * 1024}
			}
			if err != nil || got != want {
				t.Errorf("placement=%s value=%q: got %+v, %v, want %+v", placement, value, got, err, want)
			}
		}
	}
}

func TestUplinkChunkSizePreservesExplicitValues(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  Range
	}{{"1", Range{64, 64}}, {"64-128", Range{64, 128}}, {"4096", Range{4096, 4096}}} {
		got, err := (&Config{UplinkChunkSize: tc.value}).GetNormalizedUplinkChunkSize()
		if err != nil || got != tc.want {
			t.Errorf("value=%q got=%+v, %v", tc.value, got, err)
		}
	}
	for _, value := range []string{"invalid", "128-64"} {
		if _, err := (&Config{UplinkChunkSize: value}).GetNormalizedUplinkChunkSize(); err == nil {
			t.Errorf("accepted invalid value %q", value)
		}
	}
}

func TestFillPacketRequestUsesDefaultChunkSize(t *testing.T) {
	for _, placement := range []string{PlacementHeader, PlacementCookie} {
		request, err := http.NewRequest("POST", "https://example.test/", nil)
		if err != nil {
			t.Fatal(err)
		}
		config := &Config{UplinkDataPlacement: placement, XPaddingBytes: "0"}
		if err := config.FillPacketRequest(request, "session", "1", []byte("payload")); err != nil {
			t.Errorf("placement=%s: %v", placement, err)
		}
	}
}
