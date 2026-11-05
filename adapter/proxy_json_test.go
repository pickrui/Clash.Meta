package adapter

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func legacyProxyJSON(p *Proxy) ([]byte, error) {
	inner, err := p.ProxyAdapter.MarshalJSON()
	if err != nil {
		return inner, err
	}
	return p.legacyJSON(inner)
}

type proxyJSONAdapter struct {
	*outbound.Base
	raw   []byte
	value any
	err   error
	calls atomic.Int64
}

func (a *proxyJSONAdapter) MarshalJSON() ([]byte, error) {
	a.calls.Add(1)
	if a.raw != nil || a.err != nil {
		return a.raw, a.err
	}
	return json.Marshal(a.value)
}

func proxyJSONFixture(name string, raw []byte) *Proxy {
	return NewProxy(&proxyJSONAdapter{
		Base: outbound.NewBase(outbound.BaseOption{
			Name: name, Type: C.Direct, ProviderName: "provider <&>",
			Interface: "en0", RoutingMark: 1234, UDP: true,
		}),
		raw: raw,
	})
}

func recordJSONProbe(p *Proxy, url string, round int) {
	record := C.DelayHistory{Time: time.Date(2026, 10, 14, 12, 0, round, 123456789, time.UTC), Delay: uint16(round)}
	p.alive.Store(round%2 == 0)
	p.history.Put(record)
	state, _ := p.extra.LoadOrStoreFn(url, func() *internalProxyState { return &internalProxyState{} })
	state.alive.Store(round%2 == 0)
	state.history.Put(record)
}

func TestProxyJSONMatchesLegacyEncoding(t *testing.T) {
	inputs := []string{
		`{"id":"fixture","type":"Direct"}`,
		`{"all":["A","B"],"hidden":false,"now":"A","type":"Selector"}`,
		`{"nested":{"a":1,"b":[true,false,null]},"type":"custom"}`,
		`{"nested":{"b":1,"a":2},"type":"custom"}`,
		`{"big":12345678901234567,"type":"custom"}`,
		`{"e":1e3,"f":1.5,"negative":-0}`,
		`{"negative":-12,"zero":0}`,
		`{"s":"a\u003cb","type":"custom"}`,
		`{"s":"a\/b","type":"custom"}`,
		`{"name":"inner name","type":"custom","udp":false}`,
		`{"type":"first","type":"last"}`,
		`{}`, `[]`, `{"a":1} `, `not json`, `{"a":"\ud800"}`,
		`{"a":"\u2028\u2029\b\f"}`,
		`{"nested":` + strings.Repeat("[", 80) + "0" + strings.Repeat("]", 80) + "}",
	}
	for i, inner := range inputs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			for _, name := range []string{"", "plain", "香港 🇭🇰 <&> \" \\ \x00\t\n\u2028\u2029", "bad \xff utf8"} {
				p := proxyJSONFixture(name, []byte(inner))
				for round := range 3 {
					want, wantErr := legacyProxyJSON(p)
					got, gotErr := p.MarshalJSON()
					require.Equal(t, wantErr, gotErr)
					require.Equal(t, string(want), string(got))
					for _, size := range []int{16, 4096} {
						var output bytes.Buffer
						writer := bufio.NewWriterSize(&output, size)
						_, err := writer.WriteString(`{"node":`)
						require.NoError(t, err)
						require.NoError(t, WriteProxyJSON(writer, p))
						_, err = writer.WriteString("}\n")
						require.NoError(t, err)
						require.NoError(t, writer.Flush())
						require.Equal(t, `{"node":`+string(want)+"}\n", output.String())
					}
					for _, url := range []string{"https://b.test/?a=<&>", "https://a.test/香港"} {
						recordJSONProbe(p, url, round)
					}
				}
			}
		})
	}
	p := proxyJSONFixture("empty-history", []byte(`{}`))
	p.extra.LoadOrStoreFn("https://empty.test/", func() *internalProxyState { return &internalProxyState{} })
	got, err := p.MarshalJSON()
	require.NoError(t, err)
	require.Contains(t, string(got), `"history":null`)
	require.Contains(t, string(got), `"history":[]`)
}

func TestProxyJSONPreservesErrorsAndCallsInnerOnce(t *testing.T) {
	p := proxyJSONFixture("fixture", []byte(`{"type":"Direct"}`))
	a := p.ProxyAdapter.(*proxyJSONAdapter)
	a.err = errors.New("inner failure")
	got, err := p.MarshalJSON()
	require.Equal(t, a.raw, got)
	require.ErrorIs(t, err, a.err)
	require.EqualValues(t, 1, a.calls.Load())
	a.err = nil
	a.raw = []byte(`{"unordered":true,"a":1}`)
	a.calls.Store(0)
	_, err = p.MarshalJSON()
	require.NoError(t, err)
	require.EqualValues(t, 1, a.calls.Load())
	for _, stamp := range []time.Time{
		time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("invalid", 24*3600)),
	} {
		p := proxyJSONFixture("invalid-time", []byte(`{}`))
		p.history.Put(C.DelayHistory{Time: stamp})
		_, wantErr := legacyProxyJSON(p)
		_, gotErr := p.MarshalJSON()
		require.Error(t, wantErr)
		require.EqualError(t, gotErr, wantErr.Error())
	}
	for _, offset := range []int{0, 3600, -5 * 3600, 23*3600 + 59*60} {
		p := proxyJSONFixture("time", []byte(`{}`))
		stamp := time.Date(2026, 1, 1, 0, 0, 0, 1, time.FixedZone("zone", offset))
		p.history.Put(C.DelayHistory{Time: stamp, Delay: 65535})
		want, err := legacyProxyJSON(p)
		require.NoError(t, err)
		got, err := p.MarshalJSON()
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
}

func TestProxyJSONDuringHealthUpdates(t *testing.T) {
	p := proxyJSONFixture("concurrent", []byte(`{"type":"Direct"}`))
	var workers sync.WaitGroup
	workers.Go(func() {
		for i := range 200 {
			recordJSONProbe(p, fmt.Sprintf("https://%d.test/", i%8), i)
		}
	})
	for range 4 {
		workers.Go(func() {
			for range 200 {
				data, err := p.MarshalJSON()
				if err != nil || !json.Valid(data) {
					t.Errorf("invalid concurrent JSON: %v", err)
					return
				}
				var snapshot map[string]any
				if err := json.Unmarshal(data, &snapshot); err != nil {
					t.Error(err)
					return
				}
				if len(snapshot["history"].([]any)) > defaultHistoriesNum {
					t.Error("history exceeded its bound")
				}
			}
		})
	}
	workers.Wait()
}

func FuzzProxyJSONCanonicalMembers(f *testing.F) {
	for _, seed := range []string{
		`{}`, `{"a":[true,false,null],"b":{"n":123}}`, `{"a":"香港\u003c\u2028"}`,
		`{"a":"\ud800"}`, `{"a":1e1000}`, `{"a":-0}`, `{"a":1,"a":2}`, `{"a":"\\\""}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, ok := appendCanonicalMembers(nil, data); !ok {
			return
		}
		var value any
		require.NoError(t, json.Unmarshal(data, &value))
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		require.True(t, bytes.Equal(data, encoded), "%q became %q", data, encoded)
	})
}

func BenchmarkProxyJSON(b *testing.B) {
	for _, kind := range []string{"node", "tested-node", "group-10000", "nodes-1000"} {
		b.Run(kind, func(b *testing.B) {
			count := 1
			if kind == "nodes-1000" {
				count = 1000
			}
			nodes := make([]*Proxy, count)
			for i := range nodes {
				nodes[i] = NewProxy(outbound.NewBase(outbound.BaseOption{Name: fmt.Sprintf("node-%04d", i), Type: C.Direct}))
			}
			if kind == "tested-node" {
				for i := range 10 {
					recordJSONProbe(nodes[0], "https://a.test/", i)
					recordJSONProbe(nodes[0], "https://b.test/", i)
				}
			}
			if kind == "group-10000" {
				members := make([]string, 10000)
				for i := range members {
					members[i] = fmt.Sprintf("node-%04d", i)
				}
				nodes[0] = proxyJSONFixture("group", nil)
				nodes[0].ProxyAdapter.(*proxyJSONAdapter).value = map[string]any{
					"all": members, "emptyFallback": "COMPATIBLE", "hidden": false,
					"icon": "", "now": members[0], "testUrl": "", "type": "Selector",
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := json.Marshal(nodes); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
