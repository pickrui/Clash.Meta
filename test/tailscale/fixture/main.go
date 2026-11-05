// Command fixture runs the official Tailscale test control server, DERP and
// STUN servers and one tsnet peer, so the tailscale outbound can be exercised
// without an account. It is a separate process because tailscale.com and the
// metacubex fork publish the same expvar names and cannot share a binary.
//
// It prints one JSON line describing the tailnet, then runs until stdin closes.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"

	"tailscale.com/derp/derpserver"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/net/stunserver"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	magicDNSSuffix = "tail-scale.ts.net"
	echoPort       = 8080
)

type description struct {
	Control string `json:"control"`
	Admin   string `json:"admin"`
	Peer4   string `json:"peer4"`
	Peer6   string `json:"peer6"`
	Suffix  string `json:"suffix"`
}

func main() {
	requireAuth := flag.Bool("require-auth", false, "require interactive login")
	authKey := flag.String("auth-key", "", "require this auth key")
	subnet := flag.String("subnet", "", "approve this subnet route on the peer and echo TCP on its first host")
	flag.Parse()
	netns.SetEnabled(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	control := &testcontrol.Server{
		DERPMap:        runDERPAndSTUN(ctx),
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: magicDNSSuffix,
		RequireAuth:    *requireAuth,
		RequireAuthKey: *authKey,
		Logf:           logger.Discard,
	}
	control.HTTPTestServer = httptest.NewServer(control)
	defer control.HTTPTestServer.Close()

	peer := &tsnet.Server{
		Dir:        must(os.MkdirTemp("", "tailscale-fixture-")),
		ControlURL: control.HTTPTestServer.URL,
		Hostname:   "nas",
		AuthKey:    *authKey,
		Store:      new(mem.Store),
		Ephemeral:  true,
		Logf:       logger.Discard,
	}
	defer os.RemoveAll(peer.Dir)
	defer peer.Close()
	must(0, peer.Start())
	go completePeerLogin(ctx, peer, control)
	status := must(peer.Up(ctx))
	peer4, peer6 := status.TailscaleIPs[0], status.TailscaleIPs[len(status.TailscaleIPs)-1]
	serveTCPEcho(must(peer.Listen("tcp", ":"+strconv.Itoa(echoPort))))
	serveUDPEcho(must(peer.ListenPacket("udp", netip.AddrPortFrom(peer4, echoPort).String())))
	if *subnet != "" {
		// The peer advertises the route, as `tailscale set --advertise-routes`
		// does, and control approves it for every node's network map.
		route := netip.MustParsePrefix(*subnet)
		lc := must(peer.LocalClient())
		must(lc.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs:              ipn.Prefs{AdvertiseRoutes: []netip.Prefix{route}},
			AdvertiseRoutesSet: true,
		}))
		control.SetSubnetRoutes(status.Self.PublicKey, []netip.Prefix{route})
		// A host behind the router. tsnet answers flows to routed addresses
		// through a fallback handler; a listener on such an address accepts
		// but never delivers its replies.
		host := netip.AddrPortFrom(route.Masked().Addr().Next(), echoPort)
		peer.RegisterFallbackTCPHandler(func(_, dst netip.AddrPort) (func(net.Conn), bool) {
			if dst != host {
				return nil, false
			}
			return func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}, true
		})
	}

	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/complete-auth":
			if !control.CompleteAuth(r.URL.Query().Get("url")) {
				http.Error(w, "unknown auth URL", http.StatusNotFound)
			}
		case "/expire":
			control.SetExpireAllNodes(true)
		default:
			http.NotFound(w, r)
		}
	}))
	defer admin.Close()

	must(0, json.NewEncoder(os.Stdout).Encode(description{
		Control: control.HTTPTestServer.URL,
		Admin:   admin.URL,
		Peer4:   peer4.String(),
		Peer6:   peer6.String(),
		Suffix:  magicDNSSuffix,
	}))
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// completePeerLogin approves the peer's own interactive login.
func completePeerLogin(ctx context.Context, peer *tsnet.Server, control *testcontrol.Server) {
	lc := must(peer.LocalClient())
	watcher := must(lc.WatchIPNBus(ctx, ipn.NotifyInitialState))
	defer watcher.Close()
	for {
		notify, err := watcher.Next()
		if err != nil {
			return
		}
		if notify.BrowseToURL != nil {
			control.CompleteAuth(*notify.BrowseToURL)
		}
	}
}

func runDERPAndSTUN(ctx context.Context) *tailcfg.DERPMap {
	derp := derpserver.New(key.NewNode(), logger.Discard)
	server := httptest.NewUnstartedServer(derpserver.Handler(derp))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	server.StartTLS()
	stun := stunserver.New(ctx)
	must(0, stun.Listen("127.0.0.1:0"))
	go func() { _ = stun.Serve() }()
	return &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {
		RegionID:   1,
		RegionCode: "test",
		Nodes: []*tailcfg.DERPNode{{
			Name:             "t1",
			RegionID:         1,
			HostName:         "127.0.0.1",
			IPv4:             "127.0.0.1",
			IPv6:             "none",
			STUNPort:         stun.LocalAddr().(*net.UDPAddr).Port,
			DERPPort:         server.Listener.Addr().(*net.TCPAddr).Port,
			InsecureForTests: true,
			STUNTestIP:       "127.0.0.1",
		}},
	}}}
}

func serveTCPEcho(listener net.Listener) {
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
}

func serveUDPEcho(conn net.PacketConn) {
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(buffer[:n], addr)
		}
	}()
}

func must[T any](value T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return value
}
