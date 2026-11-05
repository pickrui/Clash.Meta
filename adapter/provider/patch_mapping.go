package provider

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/age"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

const maxMappingBytes = 32 * 1024 * 1024

// ProxyMapping uses the provider's own settings and never fetches new content.
func ProxyMapping(pd P.ProxyProvider, name string) (map[string]any, error) {
	var schema *proxyProviderSchema
	var buf []byte
	var err error
	version := pd.Version()
	switch pd := pd.(type) {
	case *ProxySetProvider:
		schema = pd.mappingSchema
		buf, err = pd.ReadSnapshot(maxMappingBytes)
	case *InlineProvider:
		schema = pd.mappingSchema
	}
	if err != nil {
		return nil, err
	}
	if schema == nil {
		return nil, errors.New("provider mapping is unavailable")
	}
	if buf == nil {
		buf, err = yaml.Marshal(ProxySchema{Proxies: schema.Payload})
		if err != nil {
			return nil, err
		}
	}
	if len(buf) > maxMappingBytes {
		return nil, errors.New("provider mapping exceeds read limit")
	}
	buf, err = age.DecryptBytes(buf, schema.AgeSecretKey)
	if err != nil {
		return nil, err
	}
	if len(buf) > maxMappingBytes {
		return nil, errors.New("provider mapping exceeds read limit")
	}
	source := &ProxySchema{}
	if err := yaml.Unmarshal(buf, source); err != nil {
		proxies, convertErr := convert.ConvertsV2Ray(buf)
		if convertErr != nil {
			return nil, fmt.Errorf("%w, %w", err, convertErr)
		}
		source.Proxies = proxies
	}
	filters, err := mappingFilters(schema.Filter)
	if err != nil {
		return nil, err
	}
	var excludes []*regexp2.Regexp
	if schema.ExcludeFilter != "" {
		excludes, err = mappingFilters(schema.ExcludeFilter)
		if err != nil {
			return nil, err
		}
	}
	excludedTypes := strings.Split(schema.ExcludeType, "|")
	seen := map[string]struct{}{}
	for _, filter := range filters {
		for _, proxy := range source.Proxies {
			if schema.ExcludeType != "" {
				kind, ok := proxy["type"].(string)
				if !ok || slices.ContainsFunc(excludedTypes, func(excluded string) bool { return strings.EqualFold(kind, excluded) }) {
					continue
				}
			}
			proxyName, ok := proxy["name"].(string)
			if !ok {
				continue
			}
			excluded := false
			for _, exclude := range excludes {
				matches, err := exclude.MatchString(proxyName)
				if err != nil {
					return nil, err
				}
				if matches {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
			if schema.Filter != "" {
				matches, err := filter.MatchString(proxyName)
				if err != nil {
					return nil, err
				}
				if !matches {
					continue
				}
			}
			if _, ok := seen[proxyName]; ok {
				continue
			}
			if schema.DialerProxy != "" {
				proxy["dialer-proxy"] = schema.DialerProxy
			}
			if err := schema.Override.Apply(proxy); err != nil {
				return nil, err
			}
			if proxy["name"] == name {
				if version != pd.Version() {
					return nil, errors.New("provider changed during lookup")
				}
				if !slices.ContainsFunc(pd.Proxies(), func(p C.Proxy) bool { return p.Name() == name }) {
					return nil, errors.New("proxy is no longer available")
				}
				return proxy, nil
			}
			seen[proxyName] = struct{}{}
		}
	}
	return nil, nil
}

func mappingFilters(filter string) ([]*regexp2.Regexp, error) {
	var regs []*regexp2.Regexp
	for _, expression := range strings.Split(filter, "`") {
		reg, err := utils.CompileNameRegex(expression)
		if err != nil {
			return nil, err
		}
		regs = append(regs, reg)
	}
	return regs, nil
}
