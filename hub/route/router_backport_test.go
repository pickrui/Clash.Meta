package route

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestControllerRouterAuthentication(t *testing.T) {
	handler := router(false, "test-secret", "", Cors{AllowOrigins: []string{"https://dashboard.test"}})
	for _, tc := range []struct {
		name, method, path, authorization, upgrade string
		status                                     int
	}{
		{"missing token", "GET", "/", "", "", 401},
		{"wrong token", "GET", "/", "Bearer wrong", "", 401},
		{"wrong scheme", "GET", "/", "Basic test-secret", "", 401},
		{"valid token", "GET", "/", "Bearer test-secret", "", 200},
		{"query token requires websocket", "GET", "/?token=test-secret", "", "", 401},
		{"websocket query token", "GET", "/?token=test-secret", "", "websocket", 200},
		{"wrong websocket token", "GET", "/?token=wrong", "", "websocket", 401},
		{"mounted proxy missing token", "GET", "/proxies/absent", "", "", 401},
		{"mounted proxy authorized", "GET", "/proxies/absent", "Bearer test-secret", "", 404},
		{"mounted provider missing token", "GET", "/providers/proxies/absent", "", "", 401},
		{"mounted provider authorized", "GET", "/providers/proxies/absent", "Bearer test-secret", "", 404},
		{"unsupported method", "POST", "/", "Bearer test-secret", "", 405},
		{"unknown path", "GET", "/unknown-test-path", "Bearer test-secret", "", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, nil)
			request.Header.Set("Authorization", tc.authorization)
			request.Header.Set("Upgrade", tc.upgrade)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", response.Code, tc.status, response.Body.String())
			}
			if tc.status == 200 || tc.status == 401 {
				var body map[string]any
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if tc.status == 200 && body["hello"] != "mihomo" {
					t.Fatalf("hello response changed: %v", body)
				}
				if tc.status == 401 && body["message"] != "Unauthorized" {
					t.Fatalf("unauthorized response changed: %v", body)
				}
			}
		})
	}
}

func TestControllerRouterCORS(t *testing.T) {
	handler := router(false, "test-secret", "", Cors{AllowOrigins: []string{"https://dashboard.test"}})
	for _, tc := range []struct{ origin, allow string }{
		{"https://dashboard.test", "https://dashboard.test"},
		{"https://untrusted.test", ""},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			request := httptest.NewRequest("OPTIONS", "/configs", nil)
			request.Header.Set("Origin", tc.origin)
			request.Header.Set("Access-Control-Request-Method", "PATCH")
			request.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || response.Header().Get("Access-Control-Allow-Origin") != tc.allow {
				t.Fatalf("preflight changed: status=%d headers=%v", response.Code, response.Header())
			}
		})
	}
}

func TestControllerNestedRoutePatternAndEscapedName(t *testing.T) {
	// Match the production proxy mount shape and parameter middleware without
	// installing proxy state or triggering network delay measurements.
	outer := chi.NewRouter()
	outer.Use(authentication("test-secret"))
	proxies := chi.NewRouter()
	proxies.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName)
		r.Get("/delay", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"name":    r.Context().Value(CtxKeyProxyName).(string),
				"pattern": r.Pattern,
			})
		})
	})
	outer.Mount("/proxies", proxies)
	for _, name := range []string{"DIRECT", "HK / 香港", "100% available", "plus+space"} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "/proxies/"+url.PathEscape(name)+"/delay", nil)
			request.Header.Set("Authorization", "Bearer test-secret")
			response := httptest.NewRecorder()
			outer.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d", response.Code)
			}
			var result map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result["name"] != name || result["pattern"] != "/proxies/{name}/delay" {
				t.Fatalf("nested route changed: %v", result)
			}
		})
	}
}
