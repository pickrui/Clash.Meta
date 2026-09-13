package inbound_test

import (
	"strconv"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/internal/testutil"
	"github.com/metacubex/mihomo/listener/inbound"
)

// Pin a CA, rather than a leaf, so successful proxy traffic proves that the
// explicit verification name reached the transport's chain/name verifier.
func TestInboundNameCertVerify(t *testing.T) {
	cert := testutil.NewCertificate(t, "certificate.test")
	chain, key := cert.PEM(t)
	pin := ca.CalculateFingerprint(cert.Root.Raw)
	for _, network := range []string{"tcp", "ws", "grpc"} {
		wsPath, serviceName := "", ""
		if network == "ws" {
			wsPath = "/name"
		}
		if network == "grpc" {
			serviceName = "name"
		}
		t.Run("vmess/"+network, func(t *testing.T) {
			testInboundVMess(t, inbound.VmessOption{Certificate: chain, PrivateKey: key, WsPath: wsPath, GrpcServiceName: serviceName}, outbound.VmessOption{TLS: true, ServerName: "front.test", NameCertVerify: "certificate.test", Fingerprint: pin, Network: network, WSOpts: outbound.WSOptions{Path: "/name"}, GrpcOpts: outbound.GrpcOptions{GrpcServiceName: "name"}})
		})
		t.Run("vless/"+network, func(t *testing.T) {
			testInboundVless(t, inbound.VlessOption{Certificate: chain, PrivateKey: key, WsPath: wsPath, GrpcServiceName: serviceName}, outbound.VlessOption{TLS: true, ServerName: "front.test", NameCertVerify: "certificate.test", Fingerprint: pin, Network: network, WSOpts: outbound.WSOptions{Path: "/name"}, GrpcOpts: outbound.GrpcOptions{GrpcServiceName: "name"}})
		})
		t.Run("trojan/"+network, func(t *testing.T) {
			testInboundTrojan(t, inbound.TrojanOption{Certificate: chain, PrivateKey: key, WsPath: wsPath, GrpcServiceName: serviceName}, outbound.TrojanOption{SNI: "front.test", NameCertVerify: "certificate.test", Fingerprint: pin, Network: network, WSOpts: outbound.WSOptions{Path: "/name"}, GrpcOpts: outbound.GrpcOptions{GrpcServiceName: "name"}})
		})
	}
	t.Run("anytls", func(t *testing.T) {
		testInboundAnyTLS(t, inbound.AnyTLSOption{Certificate: chain, PrivateKey: key}, outbound.AnyTLSOption{SNI: "front.test", NameCertVerify: "certificate.test", Fingerprint: pin})
	})
	t.Run("hysteria2", func(t *testing.T) {
		testInboundHysteria2(t, inbound.Hysteria2Option{Certificate: chain, PrivateKey: key}, outbound.Hysteria2Option{SNI: "front.test", NameCertVerify: "certificate.test", Fingerprint: pin})
	})
	t.Run("tuic", func(t *testing.T) {
		testInboundTuic(t, inbound.TuicOption{Certificate: chain, PrivateKey: key}, outbound.TuicOption{SNI: "front.test", NameCertVerify: "certificate.test", Fingerprint: pin})
	})
	for _, quic := range []bool{false, true} {
		t.Run("trusttunnel/quic="+strconv.FormatBool(quic), func(t *testing.T) {
			in := inbound.TrustTunnelOption{Certificate: chain, PrivateKey: key}
			if quic {
				in.Network = []string{"udp"}
			}
			testInboundTrustTunnel(t, in, outbound.TrustTunnelOption{SNI: "front.test", NameCertVerify: "certificate.test", Fingerprint: pin, Quic: quic, HealthCheck: true})
		})
	}
}
