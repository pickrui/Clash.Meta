package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"

	"github.com/metacubex/mihomo/adapter"
	P "github.com/metacubex/mihomo/constant/provider"
)

// WriteJSON streams a provider snapshot without buffering its complete node list.
// Callers should buffer small writes and discard any partial response on error.
func WriteJSON(ctx context.Context, w io.Writer, provider P.ProxyProvider) error {
	head, ok := apiSnapshot(provider)
	if !ok {
		data, err := json.Marshal(provider)
		if err == nil {
			_, err = w.Write(data)
		}
		return err
	}
	proxies := head.Proxies
	head.Proxies = nil
	encoded, err := json.Marshal(head)
	if err != nil {
		return &json.MarshalerError{Type: reflect.TypeOf(provider), Err: err}
	}
	if proxies == nil {
		_, err = w.Write(encoded)
		return err
	}
	before, after, _ := bytes.Cut(encoded, []byte(`"proxies":null`))
	if _, err := w.Write(before); err != nil {
		return err
	}
	if _, err := io.WriteString(w, `"proxies":[`); err != nil {
		return err
	}
	for i, proxy := range proxies {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if err := adapter.WriteProxyJSON(w, proxy); err != nil {
			var marshalError *json.MarshalerError
			if errors.As(err, &marshalError) {
				return &json.MarshalerError{Type: reflect.TypeOf(provider), Err: err}
			}
			return err
		}
	}
	if _, err := io.WriteString(w, "]"); err != nil {
		return err
	}
	_, err = w.Write(after)
	return err
}

func apiSnapshot(provider P.ProxyProvider) (providerForApi, bool) {
	switch p := provider.(type) {
	case *ProxySetProvider:
		if p != nil {
			return p.apiSnapshot(), true
		}
	case *InlineProvider:
		if p != nil {
			return p.apiSnapshot(), true
		}
	case *CompatibleProvider:
		if p != nil {
			return p.apiSnapshot(), true
		}
	}
	return providerForApi{}, false
}
