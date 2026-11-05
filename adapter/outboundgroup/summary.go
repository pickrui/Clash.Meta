package outboundgroup

import C "github.com/metacubex/mihomo/constant"

// Summary omits the member list and per-node history for paged consumers.
func Summary(proxy C.ProxyAdapter) map[string]any {
	group, ok := proxy.(interface {
		Hidden() bool
		Icon() string
	})
	if !ok {
		return nil
	}
	data := map[string]any{"name": proxy.Name(), "type": proxy.Type().String(), "hidden": group.Hidden(), "icon": group.Icon()}
	switch p := proxy.(type) {
	case *Selector:
		data["now"] = p.Now()
		if p.testUrl != C.DefaultTestURL {
			data["testUrl"] = p.testUrl
		}
	case *URLTest:
		data["now"], data["fixed"], data["testUrl"] = p.Now(), p.selected.Load(), p.testUrl
	case *Fallback:
		data["now"], data["fixed"], data["testUrl"] = p.Now(), p.selected.Load(), p.testUrl
	case *LoadBalance:
		data["testUrl"] = p.testUrl
	default:
		return nil
	}
	return data
}
