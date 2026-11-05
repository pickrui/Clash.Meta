package route

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/require"
)

type controllerJSONProxy struct {
	C.Proxy
	raw   string
	err   error
	calls *atomic.Int64
}

func (p *controllerJSONProxy) MarshalJSON() ([]byte, error) {
	if p.calls != nil {
		p.calls.Add(1)
	}
	return []byte(p.raw), p.err
}

type controllerJSONProvider struct {
	P.ProxyProvider
}

func (p *controllerJSONProvider) MarshalJSON() ([]byte, error) {
	return []byte(` { "custom": "<>&", "proxies": null } `), nil
}

func controllerProvider(t testing.TB, nodes []C.Proxy) *provider.CompatibleProvider {
	t.Helper()
	p, err := provider.NewCompatibleProvider("provider <&>", nodes, provider.NewHealthCheck(nil, C.DefaultTestURL, 0, 0, true, nil))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Close()) })
	return p
}

func TestControllerJSONMatchesRender(t *testing.T) {
	oldProxies, oldProviders := tunnel.Proxies(), tunnel.Providers()
	t.Cleanup(func() { tunnel.UpdateProxies(oldProxies, oldProviders) })
	var nilProvider *provider.InlineProvider
	proxies := map[string]C.Proxy{
		"香港 <&> \" \\ \x00\n\u2028\u2029": adapter.NewProxy(outbound.NewDirect()),
		"bad \xff utf8":                   &controllerJSONProxy{raw: ` { "value" : "<>&", "number": 1e3 } `},
		"null":                            nil,
	}
	nodes := []C.Proxy{proxies["bad \xff utf8"], nil}
	compatible := controllerProvider(t, nodes)
	inline, err := provider.NewInlineProvider("inline", nil, func([]byte) ([]C.Proxy, error) { return nodes, nil }, provider.NewHealthCheck(nil, C.DefaultTestURL, 0, 0, true, nil))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, inline.Close()) })
	file, err := provider.NewProxySetProvider("file", 0, nil, nil, resource.NewFileVehicle("unused"), provider.NewHealthCheck(nil, C.DefaultTestURL, 0, 0, true, nil))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	providers := map[string]P.ProxyProvider{
		compatible.Name(): compatible, inline.Name(): inline, file.Name(): file,
		"null": nil, "typed null": nilProvider, "custom": &controllerJSONProvider{},
	}
	largeProxies := make(map[string]C.Proxy, 1000)
	largeNodes := make([]C.Proxy, 1000)
	for i := range largeNodes {
		name := fmt.Sprintf("node-%04d", i)
		largeNodes[i] = adapter.NewProxy(outbound.NewBase(outbound.BaseOption{Name: name, Type: C.Direct}))
		largeProxies[name] = largeNodes[i]
	}
	largeProvider := controllerProvider(t, largeNodes)
	for _, tc := range []struct {
		name      string
		proxies   map[string]C.Proxy
		providers map[string]P.ProxyProvider
	}{
		{"populated", proxies, providers},
		{"large", largeProxies, map[string]P.ProxyProvider{"large": largeProvider}},
		{"empty", map[string]C.Proxy{}, map[string]P.ProxyProvider{}},
		{"nil", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tunnel.UpdateProxies(tc.proxies, tc.providers)
			for _, route := range []struct {
				name    string
				handler http.HandlerFunc
				value   any
			}{
				{"proxies", getProxies, render.M{"proxies": tc.proxies}},
				{"providers", getProviders, render.M{"providers": tc.providers}},
			} {
				t.Run(route.name, func(t *testing.T) {
					request := httptest.NewRequest("GET", "/", nil)
					render.Status(request, http.StatusAccepted)
					want, got := httptest.NewRecorder(), httptest.NewRecorder()
					render.JSON(want, request, route.value)
					route.handler(got, request)
					require.Equal(t, want.Code, got.Code)
					require.Equal(t, want.Header(), got.Header())
					require.Equal(t, want.Body.String(), got.Body.String())
				})
			}
		})
	}
	for name, p := range providers {
		if p == nil {
			continue
		}
		t.Run("single/"+name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "/", nil)
			request = request.WithContext(context.WithValue(request.Context(), CtxKeyProvider, p))
			want, got := httptest.NewRecorder(), httptest.NewRecorder()
			render.JSON(want, request, p)
			getProvider(got, request)
			require.Equal(t, want.Code, got.Code)
			require.Equal(t, want.Header(), got.Header())
			require.Equal(t, want.Body.String(), got.Body.String())
		})
	}
}

func TestControllerJSONEarlyErrorsKeepHTTP500(t *testing.T) {
	for _, node := range []C.Proxy{
		&controllerJSONProxy{err: errors.New("fixture marshal failed")},
		&controllerJSONProxy{raw: `{"broken":`},
		adapter.NewProxy(&controllerJSONProxy{err: errors.New("fixture adapter failed")}),
	} {
		p := controllerProvider(t, []C.Proxy{node})
		for _, tc := range []struct {
			value any
			write func(http.ResponseWriter, *http.Request)
		}{
			{render.M{"proxies": map[string]C.Proxy{"node": node}}, func(w http.ResponseWriter, r *http.Request) { writeProxiesJSON(w, r, map[string]C.Proxy{"node": node}) }},
			{p, func(w http.ResponseWriter, r *http.Request) { writeProviderJSON(w, r, p) }},
			{render.M{"providers": map[string]P.ProxyProvider{"p": p}}, func(w http.ResponseWriter, r *http.Request) {
				writeProvidersJSON(w, r, map[string]P.ProxyProvider{"p": p})
			}},
		} {
			request := httptest.NewRequest("GET", "/", nil)
			want, got := httptest.NewRecorder(), httptest.NewRecorder()
			render.JSON(want, request, tc.value)
			tc.write(got, request)
			require.Equal(t, http.StatusInternalServerError, got.Code)
			require.Equal(t, want.Header(), got.Header())
			require.Equal(t, want.Body.String(), got.Body.String())
		}
	}
}

type controllerJSONWriter struct {
	header http.Header
	write  func([]byte) (int, error)
}

func (w *controllerJSONWriter) Header() http.Header         { return w.header }
func (w *controllerJSONWriter) WriteHeader(int)             {}
func (w *controllerJSONWriter) Write(p []byte) (int, error) { return w.write(p) }

func TestControllerJSONStopsEncodingAbandonedLists(t *testing.T) {
	const count = 1000
	for _, kind := range []string{"proxies", "provider", "providers"} {
		for _, stop := range []string{"canceled before start", "canceled during write", "write failed"} {
			t.Run(kind+"/"+stop, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var calls atomic.Int64
				proxy := &controllerJSONProxy{raw: `{"value":"` + strings.Repeat("x", 1024) + `"}`, calls: &calls}
				nodes := make([]C.Proxy, count)
				proxies := make(map[string]C.Proxy, count)
				for i := range nodes {
					nodes[i] = proxy
					proxies[fmt.Sprintf("%04d", i)] = proxy
				}
				p := controllerProvider(t, nodes)
				writes := 0
				writer := &controllerJSONWriter{header: http.Header{}, write: func(data []byte) (int, error) {
					writes++
					require.LessOrEqual(t, len(data), proxyJSONBufferSize)
					switch stop {
					case "canceled during write":
						cancel()
					case "write failed":
						return 0, io.ErrClosedPipe
					}
					return len(data), nil
				}}
				request := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
				write := func() {
					switch kind {
					case "proxies":
						writeProxiesJSON(writer, request, proxies)
					case "provider":
						writeProviderJSON(writer, request, p)
					case "providers":
						writeProvidersJSON(writer, request, map[string]P.ProxyProvider{"p": p})
					}
				}
				if stop == "canceled before start" {
					cancel()
					require.NotPanics(t, write)
					require.Zero(t, calls.Load())
					require.Zero(t, writes)
				} else {
					require.PanicsWithValue(t, http.ErrAbortHandler, write)
					require.Equal(t, 1, writes)
					require.Positive(t, calls.Load())
					require.Less(t, calls.Load(), int64(count))
				}
			})
		}
	}
}

func TestControllerJSONAbortsLateEncodingFailure(t *testing.T) {
	large := &controllerJSONProxy{raw: `{"value":"` + strings.Repeat("x", 4*proxyJSONBufferSize) + `"}`}
	failed := &controllerJSONProxy{err: errors.New("late fixture error")}
	p := controllerProvider(t, []C.Proxy{large, failed})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProviderJSON(w, r, p)
	}))
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	response, err := client.Get(server.URL)
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.NotEmpty(t, body)
	require.NotContains(t, string(body), "late fixture error")
}

func BenchmarkControllerProxyJSON(b *testing.B) {
	nodes := make([]C.Proxy, 1000)
	proxies := make(map[string]C.Proxy, len(nodes))
	for i := range nodes {
		name := fmt.Sprintf("node-%04d", i)
		nodes[i] = adapter.NewProxy(outbound.NewBase(outbound.BaseOption{Name: name, Type: C.Direct, UDP: true}))
		proxies[name] = nodes[i]
	}
	p := controllerProvider(b, nodes)
	small := map[string]C.Proxy{}
	for _, node := range nodes[:10] {
		small[node.Name()] = node
	}
	providers := map[string]P.ProxyProvider{"one": p, "two": p, "three": p}
	for _, tc := range []struct {
		name  string
		value any
		write func(http.ResponseWriter, *http.Request)
	}{
		{"small-proxies", render.M{"proxies": small}, func(w http.ResponseWriter, r *http.Request) { writeProxiesJSON(w, r, small) }},
		{"proxies", render.M{"proxies": proxies}, func(w http.ResponseWriter, r *http.Request) { writeProxiesJSON(w, r, proxies) }},
		{"provider", p, func(w http.ResponseWriter, r *http.Request) { writeProviderJSON(w, r, p) }},
		{"providers", render.M{"providers": providers}, func(w http.ResponseWriter, r *http.Request) {
			writeProvidersJSON(w, r, providers)
		}},
	} {
		for _, stream := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s/stream=%v", tc.name, stream), func(b *testing.B) {
				request := httptest.NewRequest("GET", "/", nil)
				writer := &controllerJSONWriter{header: http.Header{}, write: func(data []byte) (int, error) { return len(data), nil }}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if stream {
						tc.write(writer, request)
					} else {
						render.JSON(writer, request, tc.value)
					}
				}
			})
		}
	}
}
