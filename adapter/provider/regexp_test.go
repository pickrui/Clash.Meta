package provider

import (
	"fmt"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
)

func decodedNameOverride(t *testing.T, pattern, target string) overrideSchema {
	t.Helper()
	var override overrideSchema
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
	err := decoder.Decode(map[string]any{"proxy-name": []any{map[string]any{"pattern": pattern, "target": target}}}, &override)
	if err != nil {
		t.Fatal(err)
	}
	return override
}

func TestProviderRejectsTimedOutFiltersAndRenames(t *testing.T) {
	const pattern = `^(a+)+$`
	payload := []byte(fmt.Sprintf("proxies:\n  - {name: %s, type: direct}\n", strings.Repeat("a", 512)+"!"))
	for _, kind := range []string{"filter", "exclude-filter", "rename"} {
		t.Run(kind, func(t *testing.T) {
			var filter, exclude string
			var override overrideSchema
			switch kind {
			case "filter":
				filter = pattern
			case "exclude-filter":
				exclude = pattern
			case "rename":
				override = decodedNameOverride(t, pattern, "renamed")
			}
			parser, err := NewProxiesParser("test", nil, filter, exclude, "", "", override, "")
			if err != nil {
				t.Fatal(err)
			}
			proxies, err := parser(payload)
			if err == nil || len(proxies) != 0 || !strings.Contains(err.Error(), "timeout") {
				t.Fatalf("timed out %s became an ordinary non-match: %v", kind, err)
			}
		})
	}
}

func TestProviderBoundedRegexKeepsLookbehindAndReplacement(t *testing.T) {
	override := decodedNameOverride(t, `(?<=HK-)\d+`, "02")
	parser, err := NewProxiesParser("test", nil, `(?<=HK-)\d+`, "", "", "", override, "")
	if err != nil {
		t.Fatal(err)
	}
	proxies, err := parser([]byte("proxies:\n  - {name: HK-01, type: direct}\n  - {name: US-01, type: direct}\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, proxy := range proxies {
			_ = proxy.Close()
		}
	}()
	if len(proxies) != 1 || proxies[0].Name() != "HK-02" {
		t.Fatal("bounded regex changed supported matching or replacement syntax")
	}
}
