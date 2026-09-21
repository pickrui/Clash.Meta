package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/common"
	yamlv3 "gopkg.in/yaml.v3"
)

var tunnel P.Tunnel

func SetTunnel(t P.Tunnel) {
	tunnel = t
}

type RulePayload struct {
	/**
	key: Domain or IP Cidr
	value: Rule type or is empty
	*/
	Payload []string `yaml:"payload"`
	Rules   []string `yaml:"rules"`
}

type providerForApi struct {
	Behavior    string    `json:"behavior"`
	Format      string    `json:"format"`
	Name        string    `json:"name"`
	RuleCount   int       `json:"ruleCount"`
	Type        string    `json:"type"`
	VehicleType string    `json:"vehicleType"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Payload     []string  `json:"payload,omitempty"`
}

type ruleStrategy interface {
	Behavior() P.RuleBehavior
	Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool
	Count() int
	Reset()
	Insert(rule string)
	FinishInsert()
}

type mrsRuleStrategy interface {
	ruleStrategy
	FromMrs(r io.Reader, count int) error
	WriteMrs(w io.Writer) error
	DumpMrs(f func(key string) bool)
}

type baseProvider struct {
	behavior P.RuleBehavior
	strategy atomic.TypedValue[ruleStrategy]
}

func (bp *baseProvider) Type() P.ProviderType {
	return P.Rule
}

func (bp *baseProvider) Behavior() P.RuleBehavior {
	return bp.behavior
}

func (bp *baseProvider) Count() int {
	return bp.strategy.Load().Count()
}

func (bp *baseProvider) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	strategy := bp.strategy.Load()
	return strategy != nil && strategy.Match(metadata, helper)
}

func (bp *baseProvider) Strategy() any {
	return bp.strategy.Load()
}

type ruleSetProvider struct {
	baseProvider
	*resource.Fetcher[ruleStrategy]
	format P.RuleFormat
}

type RuleSetProvider struct {
	*ruleSetProvider
}

func (rp *ruleSetProvider) Initial() error {
	_, err := rp.Fetcher.Initial()
	return err
}

func (rp *ruleSetProvider) Update() error {
	_, _, err := rp.Fetcher.Update()
	return err
}

func (rp *ruleSetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		providerForApi{
			Behavior:    rp.behavior.String(),
			Format:      rp.format.String(),
			Name:        rp.Fetcher.Name(),
			RuleCount:   rp.Count(),
			Type:        rp.Type().String(),
			UpdatedAt:   rp.UpdatedAt(),
			VehicleType: rp.VehicleType().String(),
		})
}

func (rp *RuleSetProvider) Close() error {
	runtime.SetFinalizer(rp, nil)
	return rp.ruleSetProvider.Close()
}

func NewRuleSetProvider(name string, behavior P.RuleBehavior, format P.RuleFormat, interval time.Duration, vehicle P.Vehicle, payload []string, bundleFile resource.BundleFile, parse common.ParseRuleFunc) P.RuleProvider {
	rp := &ruleSetProvider{
		baseProvider: baseProvider{
			behavior: behavior,
		},
		format: format,
	}

	onUpdate := func(strategy ruleStrategy) {
		rp.strategy.Store(strategy)
		tunnel.RuleUpdateCallback().Emit(rp)
	}

	strategy := newStrategy(behavior, parse)
	if len(payload) > 0 { // using as fallback rules
		strategy = rulesParseInline(payload, strategy)
	}
	rp.strategy.Store(strategy)
	rp.Fetcher = resource.NewFetcher(name, interval, vehicle, bundleFile, func(bytes []byte) (ruleStrategy, error) {
		return rulesParse(bytes, newStrategy(behavior, parse), format)
	}, onUpdate)

	wrapper := &RuleSetProvider{
		rp,
	}

	runtime.SetFinalizer(wrapper, (*RuleSetProvider).Close)
	return wrapper
}

func newStrategy(behavior P.RuleBehavior, parse common.ParseRuleFunc) ruleStrategy {
	switch behavior {
	case P.Domain:
		strategy := NewDomainStrategy()
		return strategy
	case P.IPCIDR:
		strategy := NewIPCidrStrategy()
		return strategy
	case P.Classical:
		strategy := NewClassicalStrategy(parse)
		return strategy
	default:
		return nil
	}
}

var (
	ErrNoPayload     = errors.New("file must have a `payload` field")
	ErrInvalidFormat = errors.New("invalid format")
)

func rulesParse(buf []byte, strategy ruleStrategy, format P.RuleFormat) (ruleStrategy, error) {
	strategy.Reset()
	if format == P.MrsRule {
		return rulesMrsParse(buf, strategy)
	}

	schema := &RulePayload{}

	firstLineBuffer := pool.GetBuffer()
	defer pool.PutBuffer(firstLineBuffer)
	firstLineLength := 0
	sequenceIndent := -1

	s := 0 // search start index
	for s < len(buf) {
		// search buffer for a new line.
		line := buf[s:]
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			i += s
			line = buf[s : i+1]
			s = i + 1
		} else {
			s = len(buf)                                      // stop loop in next step
			if firstLineLength == 0 && format == P.YamlRule { // no head or only one line body
				return rulesParseYAMLDocument(buf, strategy)
			}
		}
		var str string
		switch format {
		case P.TextRule:
			str = string(line)
			str = strings.TrimSpace(str)
			if len(str) == 0 {
				continue
			}
			if str[0] == '#' { // comment
				continue
			}
			if strings.HasPrefix(str, "//") { // comment in Premium core
				continue
			}
		case P.YamlRule:
			trimLine := bytes.TrimSpace(line)
			if len(trimLine) == 0 {
				continue
			}
			if trimLine[0] == '#' { // comment
				continue
			}
			firstLineBuffer.Write(line)
			if firstLineLength == 0 { // find payload head
				firstLineLength = firstLineBuffer.Len()
				firstLineBuffer.WriteString("  - ''") // a test line

				err := yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
				firstLineBuffer.Truncate(firstLineLength)
				if err == nil && (len(schema.Rules) > 0 || len(schema.Payload) > 0) { // found
					continue
				}

				return rulesParseYAMLDocument(buf, strategy)
			}

			indent := len(line) - len(bytes.TrimLeft(line, " "))
			if indent >= len(line) || line[indent] != '-' ||
				(len(trimLine) > 1 && trimLine[1] != ' ' && trimLine[1] != '\t') ||
				(sequenceIndent >= 0 && sequenceIndent != indent) {
				return rulesParseYAMLDocument(buf, strategy)
			}
			sequenceIndent = indent
			// Uncertain syntax must be validated as a complete document before publication.
			*schema = RulePayload{}
			err := yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
			firstLineBuffer.Truncate(firstLineLength)
			if err != nil || len(schema.Rules)+len(schema.Payload) != 1 {
				return rulesParseYAMLDocument(buf, strategy)
			}

			if len(schema.Rules) > 0 {
				str = schema.Rules[0]
			}
			if len(schema.Payload) > 0 {
				str = schema.Payload[0]
			}
		default:
			return nil, ErrInvalidFormat
		}

		if str == "" {
			continue
		}

		strategy.Insert(str)
	}

	if format == P.YamlRule && strategy.Count() == 0 {
		return rulesParseYAMLDocument(buf, strategy)
	}
	strategy.FinishInsert()

	return strategy, nil
}

func rulesParseYAMLDocument(buf []byte, strategy ruleStrategy) (ruleStrategy, error) {
	var schema RulePayload
	decoder := yamlv3.NewDecoder(bytes.NewReader(buf))
	if err := decoder.Decode(&schema); err != nil {
		return nil, err
	}
	var extra yamlv3.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, ErrInvalidFormat
	}
	rules := schema.Payload
	if rules == nil {
		rules = schema.Rules
	}
	if rules == nil {
		return nil, ErrNoPayload
	}
	return rulesParseInline(rules, strategy), nil
}

func rulesParseInline(rs []string, strategy ruleStrategy) ruleStrategy {
	strategy.Reset()
	for _, r := range rs {
		if r != "" {
			strategy.Insert(r)
		}
	}
	strategy.FinishInsert()
	return strategy
}

type InlineProvider struct {
	*inlineProvider
}

type inlineProvider struct {
	baseProvider
	name     string
	updateAt time.Time
	payload  []string
}

func (i *inlineProvider) Name() string {
	return i.name
}

func (i *inlineProvider) Initial() error {
	return nil
}

func (i *inlineProvider) Update() error {
	// make api update happy
	i.updateAt = time.Now()
	return nil
}

func (i *inlineProvider) VehicleType() P.VehicleType {
	return P.Inline
}

func (i *inlineProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		providerForApi{
			Behavior:    i.behavior.String(),
			Name:        i.Name(),
			RuleCount:   i.Count(),
			Type:        i.Type().String(),
			VehicleType: i.VehicleType().String(),
			UpdatedAt:   i.updateAt,
			Payload:     i.payload,
		})
}

func NewInlineProvider(name string, behavior P.RuleBehavior, payload []string, parse common.ParseRuleFunc) P.RuleProvider {
	ip := &inlineProvider{
		baseProvider: baseProvider{
			behavior: behavior,
		},
		payload:  payload,
		name:     name,
		updateAt: time.Now(),
	}
	ip.strategy.Store(rulesParseInline(payload, newStrategy(behavior, parse)))

	wrapper := &InlineProvider{
		ip,
	}

	//runtime.SetFinalizer(wrapper, (*InlineProvider).Close)
	return wrapper
}
