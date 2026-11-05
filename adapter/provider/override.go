package provider

import (
	"encoding"
	"fmt"

	"github.com/dlclark/regexp2"
	"github.com/metacubex/mihomo/common/utils"
)

type overrideSchema struct {
	TFO            *bool   `provider:"tfo,omitempty"`
	MPTcp          *bool   `provider:"mptcp,omitempty"`
	UDP            *bool   `provider:"udp,omitempty"`
	UDPOverTCP     *bool   `provider:"udp-over-tcp,omitempty"`
	Up             *string `provider:"up,omitempty"`
	Down           *string `provider:"down,omitempty"`
	DialerProxy    *string `provider:"dialer-proxy,omitempty"`
	SkipCertVerify *bool   `provider:"skip-cert-verify,omitempty"`
	NameCertVerify *string `provider:"name-cert-verify,omitempty"`
	Interface      *string `provider:"interface-name,omitempty"`
	RoutingMark    *int    `provider:"routing-mark,omitempty"`
	IPVersion      *string `provider:"ip-version,omitempty"`

	AdditionalPrefix *string                   `provider:"additional-prefix,omitempty"`
	AdditionalSuffix *string                   `provider:"additional-suffix,omitempty"`
	ProxyName        []overrideProxyNameSchema `provider:"proxy-name,omitempty"`
	OverrideExpr     []OverrideExpr            `provider:"override-expr,omitempty"`
}

type overrideProxyNameSchema struct {
	// matching expression for regex replacement
	Pattern *namePattern `provider:"pattern"`
	// the new content after regex matching
	Target string `provider:"target"`
}

type namePattern struct {
	*regexp2.Regexp
}

func (p *namePattern) UnmarshalText(text []byte) error {
	compiled, err := utils.CompileNameRegex(string(text))
	if err == nil {
		p.Regexp = compiled
	}
	return err
}

var _ encoding.TextUnmarshaler = (*namePattern)(nil)

func (o *overrideSchema) Apply(mapping map[string]any) error {
	if o.TFO != nil {
		mapping["tfo"] = *o.TFO
	}
	if o.MPTcp != nil {
		mapping["mptcp"] = *o.MPTcp
	}
	if o.UDP != nil {
		mapping["udp"] = *o.UDP
	}
	if o.UDPOverTCP != nil {
		mapping["udp-over-tcp"] = *o.UDPOverTCP
	}
	if o.Up != nil {
		mapping["up"] = *o.Up
	}
	if o.Down != nil {
		mapping["down"] = *o.Down
	}
	if o.DialerProxy != nil {
		mapping["dialer-proxy"] = *o.DialerProxy
	}
	if o.SkipCertVerify != nil {
		mapping["skip-cert-verify"] = *o.SkipCertVerify
	}
	if o.NameCertVerify != nil {
		mapping["name-cert-verify"] = *o.NameCertVerify
	}
	if o.Interface != nil {
		mapping["interface-name"] = *o.Interface
	}
	if o.RoutingMark != nil {
		mapping["routing-mark"] = *o.RoutingMark
	}
	if o.IPVersion != nil {
		mapping["ip-version"] = *o.IPVersion
	}

	for _, expr := range o.ProxyName {
		name := mapping["name"].(string)
		newName, err := expr.Pattern.Replace(name, expr.Target, 0, -1)
		if err != nil {
			return fmt.Errorf("proxy name replace error: %w", err)
		}
		mapping["name"] = newName
	}
	if o.AdditionalPrefix != nil {
		mapping["name"] = fmt.Sprintf("%s%s", *o.AdditionalPrefix, mapping["name"])
	}
	if o.AdditionalSuffix != nil {
		mapping["name"] = fmt.Sprintf("%s%s", mapping["name"], *o.AdditionalSuffix)
	}
	for idx, expr := range o.OverrideExpr {
		if err := expr.Apply(mapping); err != nil {
			return fmt.Errorf("override-expr[%d] %q: %w", idx, expr.String(), err)
		}
	}

	return nil
}
