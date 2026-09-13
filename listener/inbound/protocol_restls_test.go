package inbound_test

import (
	"net"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
)

func protocolRestlsOptions() (inbound.ResTLS, outbound.RestlsOptions) {
	return inbound.ResTLS{Enable: true, Dest: net.JoinHostPort(realityDest, "443"), Password: "restls-password", RateLimit: 1},
		outbound.RestlsOptions{Password: "restls-password", VersionHint: "tls13"}
}

func TestInboundVMess_Restls(t *testing.T) {
	for _, network := range []string{"tcp", "ws", "ws-early", "http-upgrade", "grpc"} {
		t.Run(network, func(t *testing.T) {
			server, client := protocolRestlsOptions()
			in := inbound.VmessOption{ResTLS: server}
			out := outbound.VmessOption{TLS: true, ServerName: realityDest, Fingerprint: tlsFingerprint, ClientFingerprint: "chrome", RestlsOpts: client, Network: network}
			if network == "ws" || network == "ws-early" || network == "http-upgrade" {
				in.WsPath = "/restls"
				out.Network = "ws"
				out.WSOpts.Path = in.WsPath
				if network == "ws-early" {
					out.WSOpts.Path += "?ed=2048"
				}
				if network == "http-upgrade" {
					out.WSOpts.V2rayHttpUpgrade = true
				}
			}
			if network == "grpc" {
				in.GrpcServiceName = "restls"
				out.GrpcOpts.GrpcServiceName = "restls"
			}
			testInboundVMess(t, in, out)
		})
	}
}

func TestInboundVless_Restls(t *testing.T) {
	for _, network := range []string{"tcp", "ws", "ws-early", "http-upgrade", "grpc"} {
		t.Run(network, func(t *testing.T) {
			server, client := protocolRestlsOptions()
			in := inbound.VlessOption{ResTLS: server}
			out := outbound.VlessOption{TLS: true, ServerName: realityDest, Fingerprint: tlsFingerprint, ClientFingerprint: "chrome", RestlsOpts: client, Network: network}
			if network == "ws" || network == "ws-early" || network == "http-upgrade" {
				in.WsPath = "/restls"
				out.Network = "ws"
				out.WSOpts.Path = in.WsPath
				if network == "ws-early" {
					out.WSOpts.Path += "?ed=2048"
				}
				if network == "http-upgrade" {
					out.WSOpts.V2rayHttpUpgrade = true
				}
			}
			if network == "grpc" {
				in.GrpcServiceName = "restls"
				out.GrpcOpts.GrpcServiceName = "restls"
			}
			testInboundVless(t, in, out)
		})
	}
	for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
		for _, alpn := range []string{"http/1.1", "h2"} {
			t.Run("xhttp/"+mode+"/"+alpn, func(t *testing.T) {
				server, client := protocolRestlsOptions()
				in := inbound.VlessOption{ResTLS: server, XHTTPConfig: inbound.XHTTPConfig{Mode: mode, Path: "/restls"}}
				out := outbound.VlessOption{TLS: true, ServerName: realityDest, Fingerprint: tlsFingerprint, ClientFingerprint: "chrome", RestlsOpts: client, Network: "xhttp", ALPN: []string{alpn}, XHTTPOpts: outbound.XHTTPOptions{Mode: mode, Path: "/restls"}}
				if mode != "stream-one" {
					out.XHTTPOpts.DownloadSettings = &outbound.XHTTPDownloadSettings{}
				}
				testInboundVless(t, in, out)
			})
		}
	}
}

func TestInboundTrojan_Restls(t *testing.T) {
	for _, network := range []string{"tcp", "ws", "ws-early", "http-upgrade", "grpc"} {
		t.Run(network, func(t *testing.T) {
			server, client := protocolRestlsOptions()
			in := inbound.TrojanOption{ResTLS: server}
			out := outbound.TrojanOption{SNI: realityDest, Fingerprint: tlsFingerprint, ClientFingerprint: "chrome", RestlsOpts: client, Network: network}
			if network == "ws" || network == "ws-early" || network == "http-upgrade" {
				in.WsPath = "/restls"
				out.Network = "ws"
				out.WSOpts.Path = in.WsPath
				if network == "ws-early" {
					out.WSOpts.Path += "?ed=2048"
				}
				if network == "http-upgrade" {
					out.WSOpts.V2rayHttpUpgrade = true
				}
			}
			if network == "grpc" {
				in.GrpcServiceName = "restls"
				out.GrpcOpts.GrpcServiceName = "restls"
			}
			testInboundTrojan(t, in, out)
		})
	}
}
