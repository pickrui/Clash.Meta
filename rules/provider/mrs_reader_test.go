package provider

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"github.com/klauspost/compress/zstd"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

func mrsSource(t testing.TB, behavior P.RuleBehavior, count, extra int) []byte {
	t.Helper()
	strategy := newStrategy(behavior, nil)
	strategy.Reset()
	for i := range count {
		if behavior == P.Domain {
			strategy.Insert(fmt.Sprintf("+.host-%08x-%d.example.com", uint32(i)*2654435761, i))
		} else {
			strategy.Insert(fmt.Sprintf("10.%d.%d.%d/32", i>>15, i>>7&255, i<<1&255))
		}
	}
	strategy.FinishInsert()
	var plain bytes.Buffer
	plain.Write(MrsMagicBytes[:])
	plain.WriteByte(behavior.Byte())
	for _, value := range []int64{int64(strategy.Count()), int64(extra)} {
		if err := binary.Write(&plain, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	plain.Write(make([]byte, extra))
	if err := strategy.(mrsRuleStrategy).WriteMrs(&plain); err != nil {
		t.Fatal(err)
	}
	return plain.Bytes()
}

func compressMrs(t testing.TB, plain []byte) []byte {
	t.Helper()
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	return encoder.EncodeAll(plain, nil)
}

func TestMrsDecodeCompatibility(t *testing.T) {
	for _, behavior := range []P.RuleBehavior{P.Domain, P.IPCIDR} {
		for _, extra := range []int{0, 257, 256 << 10} {
			t.Run(fmt.Sprintf("%s/extra=%d", behavior, extra), func(t *testing.T) {
				plain := mrsSource(t, behavior, 10000, extra)
				encoded := compressMrs(t, plain)
				t.Parallel()
				parsed, err := rulesMrsParse(encoded, newStrategy(behavior, nil))
				if err != nil {
					t.Fatal(err)
				}
				if parsed.Count() != 10000 {
					t.Fatalf("rule count = %d", parsed.Count())
				}
				for _, i := range []int{0, 4999, 9999} {
					metadata := &C.Metadata{Host: fmt.Sprintf("www.host-%08x-%d.example.com", uint32(i)*2654435761, i)}
					metadata.DstIP = netip.AddrFrom4([4]byte{10, byte(i >> 15), byte(i >> 7), byte(i << 1)})
					if !parsed.Match(metadata, C.RuleMatchHelper{}) {
						t.Errorf("rule %d did not match", i)
					}
				}
				if parsed.Match(&C.Metadata{Host: "miss.example", DstIP: netip.MustParseAddr("10.0.0.1")}, C.RuleMatchHelper{}) {
					t.Error("unexpected rule match")
				}
				var written bytes.Buffer
				if err := parsed.(mrsRuleStrategy).WriteMrs(&written); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(written.Bytes(), plain[21+extra:]) {
					t.Fatal("decoded rule structure changed")
				}
			})
		}
	}
}

func TestMrsDecodeInvalidInput(t *testing.T) {
	valid := mrsSource(t, P.Domain, 20, 0)
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"magic", func(b []byte) []byte { b[0] = 'X'; return b }},
		{"behavior", func(b []byte) []byte { b[4] = P.IPCIDR.Byte(); return b }},
		{"negative extra", func(b []byte) []byte { binary.BigEndian.PutUint64(b[13:21], ^uint64(0)); return b }},
		{"oversized extra", func(b []byte) []byte { binary.BigEndian.PutUint64(b[13:21], 1<<62); return b }},
		{"short extra", func(b []byte) []byte { binary.BigEndian.PutUint64(b[13:21], 1024); return b[:32] }},
		{"short header", func(b []byte) []byte { return b[:15] }},
		{"short rules", func(b []byte) []byte { return b[:len(b)-1] }},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded := compressMrs(t, test.mutate(bytes.Clone(valid)))
			if _, err := rulesMrsParse(encoded, NewDomainStrategy()); err == nil {
				t.Fatal("invalid MRS accepted")
			}
		})
	}
	encoded := compressMrs(t, valid)
	if _, err := rulesMrsParse(encoded[:len(encoded)/2], NewDomainStrategy()); err == nil {
		t.Fatal("truncated zstd frame accepted")
	}
}

func BenchmarkMrsDecode(b *testing.B) {
	for _, behavior := range []P.RuleBehavior{P.Domain, P.IPCIDR} {
		for _, count := range []int{10000, 100000} {
			b.Run(fmt.Sprintf("%s/%d", behavior, count), func(b *testing.B) {
				plain := mrsSource(b, behavior, count, 0)
				encoded := compressMrs(b, plain)
				b.SetBytes(int64(len(plain)))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := rulesMrsParse(encoded, newStrategy(behavior, nil)); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
	b.Run("reserved8MiB", func(b *testing.B) {
		encoded := compressMrs(b, mrsSource(b, P.Domain, 20, 8<<20))
		b.ReportAllocs()
		for b.Loop() {
			if _, err := rulesMrsParse(encoded, NewDomainStrategy()); err != nil {
				b.Fatal(err)
			}
		}
	})
}
