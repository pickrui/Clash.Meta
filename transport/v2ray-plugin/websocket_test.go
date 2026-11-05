package obfs

import "testing"

func TestWebsocketConfigKeepsExplicitServerName(t *testing.T) {
	config, err := newWebsocketConfig(&Option{
		Host:       "request.example",
		ServerName: "ech.example",
		Headers:    map[string]string{"Host": "front.example"},
		TLS:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.TLSConfig.ServerName != "ech.example" {
		t.Fatalf("TLS ServerName = %q", config.TLSConfig.ServerName)
	}
	if got := config.Headers.Get("Host"); got != "front.example" {
		t.Fatalf("HTTP Host = %q", got)
	}
}

func TestWebsocketConfigDefaultsServerNameToHost(t *testing.T) {
	config, err := newWebsocketConfig(&Option{Host: "request.example", TLS: true})
	if err != nil {
		t.Fatal(err)
	}
	if config.TLSConfig.ServerName != "request.example" {
		t.Fatalf("TLS ServerName = %q", config.TLSConfig.ServerName)
	}
}
