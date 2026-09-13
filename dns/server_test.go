package dns

import (
	"context"
	"net"
	"testing"

	D "github.com/miekg/dns"
)

type largeReplyService struct{}

func (largeReplyService) ServeMsg(_ context.Context, query *D.Msg) (*D.Msg, error) {
	reply := new(D.Msg).SetReply(query)
	for i := 0; i < 150; i++ {
		reply.Answer = append(reply.Answer, &D.A{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, byte(i))})
	}
	return reply, nil
}

type dnsResponseRecorder struct {
	D.ResponseWriter
	remote net.Addr
	data   []byte
}

func (r *dnsResponseRecorder) RemoteAddr() net.Addr            { return r.remote }
func (r *dnsResponseRecorder) WriteMsg(msg *D.Msg) (err error) { r.data, err = msg.Pack(); return }

func TestServerTruncatesOnlyUDP(t *testing.T) {
	for _, tc := range []struct {
		name  string
		size  uint16
		tcp   bool
		limit int
	}{
		{"legacy", 0, false, 512}, {"small-edns", 100, false, 512},
		{"edns", 1232, false, 1232}, {"large-edns", 4096, false, 4096},
		{"tcp", 512, true, 65535},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := new(D.Msg).SetQuestion("large-response.example.test.", D.TypeA)
			if tc.size > 0 {
				query.SetEdns0(tc.size, false)
			}
			writer := &dnsResponseRecorder{remote: &net.UDPAddr{}}
			if tc.tcp {
				writer.remote = &net.TCPAddr{}
			}
			(&Server{service: largeReplyService{}}).ServeDNS(writer, query)
			if len(writer.data) > tc.limit {
				t.Fatalf("response size %d exceeds %d", len(writer.data), tc.limit)
			}
			reply := new(D.Msg)
			if err := reply.Unpack(writer.data); err != nil {
				t.Fatal(err)
			}
			wantTruncated := tc.limit < 2400
			if reply.Truncated != wantTruncated {
				t.Fatalf("TC=%t, want %t", reply.Truncated, wantTruncated)
			}
			if !wantTruncated && len(reply.Answer) != 150 {
				t.Fatalf("lost answers: %d", len(reply.Answer))
			}
		})
	}
}
