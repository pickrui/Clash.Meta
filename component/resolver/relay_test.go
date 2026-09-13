package resolver

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

type relayTestService struct {
	answers int
	err     error
}

func (s relayTestService) ServeMsg(_ context.Context, query *D.Msg) (*D.Msg, error) {
	if s.err != nil {
		return nil, s.err
	}
	reply := new(D.Msg).SetReply(query)
	for i := 0; i < s.answers; i++ {
		reply.Answer = append(reply.Answer, &D.A{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, byte(i))})
	}
	return reply, nil
}

func useRelayTestService(t *testing.T, service Service) {
	t.Helper()
	old := DefaultService
	DefaultService = service
	t.Cleanup(func() { DefaultService = old })
}

func TestRelayDNSPacketCopiesReallocatedCompressedData(t *testing.T) {
	useRelayTestService(t, relayTestService{answers: 100})
	query := new(D.Msg).SetQuestion("long-repeated-name.example.test.", D.TypeA).SetEdns0(4096, false)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	target := bytes.Repeat([]byte{0xa5}, SafeDnsPacketSize)
	data, err := RelayDnsPacket(context.Background(), payload, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || &data[0] != &target[0] {
		t.Fatal("packed data is not backed by the caller buffer")
	}
	reply := new(D.Msg)
	if err := reply.Unpack(target[:len(data)]); err != nil {
		t.Fatal(err)
	}
	if len(reply.Answer) != 100 || reply.Truncated || reply.Id != query.Id {
		t.Fatalf("corrupted reply: answers=%d TC=%t id=%d", len(reply.Answer), reply.Truncated, reply.Id)
	}
}

func TestRelayDNSPacketRespectsClientUDPSize(t *testing.T) {
	useRelayTestService(t, relayTestService{answers: 150})
	for _, tc := range []struct {
		name  string
		size  uint16
		limit int
	}{
		{"legacy", 0, 512}, {"small-edns", 100, 512}, {"edns", 1232, 1232}, {"relay-cap", 4096, SafeDnsPacketSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := new(D.Msg).SetQuestion("large-response.example.test.", D.TypeA)
			if tc.size > 0 {
				query.SetEdns0(tc.size, false)
			}
			payload, err := query.Pack()
			if err != nil {
				t.Fatal(err)
			}
			data, err := RelayDnsPacket(context.Background(), payload, make([]byte, SafeDnsPacketSize))
			if err != nil {
				t.Fatal(err)
			}
			if len(data) > tc.limit {
				t.Fatalf("response size %d exceeds %d", len(data), tc.limit)
			}
			reply := new(D.Msg)
			if err := reply.Unpack(data); err != nil {
				t.Fatal(err)
			}
			if !reply.Truncated {
				t.Fatal("missing TC flag")
			}
		})
	}
}

func TestRelayDNSTCPKeepsLargeAnswers(t *testing.T) {
	useRelayTestService(t, relayTestService{answers: 150})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() { done <- RelayDnsConn(context.Background(), server, time.Second) }()
	query := new(D.Msg).SetQuestion("large-response.example.test.", D.TypeA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	request := make([]byte, len(payload)+2)
	binary.BigEndian.PutUint16(request, uint16(len(payload)))
	copy(request[2:], payload)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	var length uint16
	if err := binary.Read(client, binary.BigEndian, &length); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(client, data); err != nil {
		t.Fatal(err)
	}
	reply := new(D.Msg)
	if err := reply.Unpack(data); err != nil {
		t.Fatal(err)
	}
	if reply.Truncated || len(reply.Answer) != 150 {
		t.Fatalf("TCP lost answers: %d TC=%t", len(reply.Answer), reply.Truncated)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRelayDNSPacketFailureResponse(t *testing.T) {
	useRelayTestService(t, relayTestService{err: errors.New("lookup failed")})
	query := new(D.Msg).SetQuestion("failure.example.test.", D.TypeA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	data, err := RelayDnsPacket(context.Background(), payload, make([]byte, SafeDnsPacketSize))
	if err != nil {
		t.Fatal(err)
	}
	reply := new(D.Msg)
	if err := reply.Unpack(data); err != nil {
		t.Fatal(err)
	}
	if reply.Rcode != D.RcodeServerFailure || reply.Id != query.Id {
		t.Fatal("missing SERVFAIL response")
	}
	if _, err := RelayDnsPacket(context.Background(), []byte{1, 2, 3}, nil); err == nil {
		t.Fatal("malformed request was accepted")
	}
}
