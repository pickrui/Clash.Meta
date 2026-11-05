package adapter

import (
	"bytes"
	"cmp"
	"encoding/json"
	"io"
	"reflect"
	"slices"
	"strconv"
	"unicode/utf8"

	C "github.com/metacubex/mihomo/constant"
)

// WriteProxyJSON reuses a buffered writer's free space for ordinary proxies.
func WriteProxyJSON(w io.Writer, proxy C.Proxy) error {
	var data []byte
	var err error
	if p, ok := proxy.(*Proxy); ok && p != nil {
		if buffered, ok := w.(interface{ AvailableBuffer() []byte }); ok {
			data = buffered.AvailableBuffer()
		}
		if data, err = p.encodeJSON(data); err != nil {
			err = &json.MarshalerError{Type: reflect.TypeFor[C.Proxy](), Err: err}
		}
	} else {
		// Keep the interface marshaler's validation, escaping and error type.
		data, err = json.Marshal(&proxy)
	}
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func (p *Proxy) appendMergedJSON(b, inner []byte) ([]byte, bool) {
	info := p.ProxyInfo()
	extra, err := p.appendExtraJSON(nil)
	if err != nil {
		return b, false
	}
	history, err := appendDelayHistory(nil, p.history.Copy(), false)
	if err != nil {
		return b, false
	}
	fields := append(make([]jsonMember, 0, 24), []jsonMember{
		{key: "alive", value: jsonBool(p.alive.Load())},
		{key: "dialer-proxy", value: AppendJSONString(nil, info.DialerProxy)},
		{key: "extra", value: extra},
		{key: "history", value: history},
		{key: "interface", value: AppendJSONString(nil, info.Interface)},
		{key: "mptcp", value: jsonBool(info.MPTCP)},
		{key: "name", value: AppendJSONString(nil, p.Name())},
		{key: "provider-name", value: AppendJSONString(nil, info.ProviderName)},
		{key: "routing-mark", value: strconv.AppendInt(nil, int64(info.RoutingMark), 10)},
		{key: "smux", value: jsonBool(info.SMUX)},
		{key: "tfo", value: jsonBool(info.TFO)},
		{key: "udp", value: jsonBool(p.SupportUDP())},
		{key: "uot", value: jsonBool(p.SupportUOT())},
		{key: "xudp", value: jsonBool(info.XUDP)},
	}...)
	wrapper := len(fields)
	fields, ok := appendCanonicalMembers(fields, inner)
	if !ok {
		return b, false
	}
	merged := fields[:wrapper]
	for _, member := range fields[wrapper:] {
		if !slices.ContainsFunc(fields[:wrapper], func(field jsonMember) bool { return field.key == member.key }) {
			merged = append(merged, member)
		}
	}
	sortMembers(merged)
	size := 2
	for _, field := range merged {
		size += len(field.key) + len(field.value) + 4
	}
	b = slices.Grow(b, size)
	b = append(b, '{')
	for i, field := range merged {
		if i > 0 {
			b = append(b, ',')
		}
		b = AppendJSONString(b, field.key)
		b = append(b, ':')
		b = append(b, field.value...)
	}
	return append(b, '}'), true
}

var jsonTrue, jsonFalse = []byte("true"), []byte("false")

func jsonBool(v bool) []byte {
	if v {
		return jsonTrue
	}
	return jsonFalse
}

type jsonMember struct {
	key   string
	value []byte
}

func sortMembers(members []jsonMember) {
	slices.SortFunc(members, func(a, b jsonMember) int { return cmp.Compare(a.key, b.key) })
}

func appendCanonicalMembers(members []jsonMember, data []byte) ([]jsonMember, bool) {
	s := jsonScan{data: data}
	if !s.object(func(key string, value []byte) bool {
		members = append(members, jsonMember{key: key, value: value})
		return true
	}) || s.i != len(data) {
		return members, false
	}
	return members, true
}

type jsonScan struct {
	data  []byte
	i     int
	depth int
}

func (s *jsonScan) peek() byte {
	if s.i < len(s.data) {
		return s.data[s.i]
	}
	return 0
}

func (s *jsonScan) object(member func(key string, value []byte) bool) bool {
	if s.peek() != '{' {
		return false
	}
	s.i++
	if s.peek() == '}' {
		s.i++
		return true
	}
	previous, first := "", true
	for {
		key, ok := s.string()
		if !ok || (!first && key <= previous) || s.peek() != ':' {
			return false
		}
		previous, first = key, false
		s.i++
		start := s.i
		if !s.value() || !member(key, s.data[start:s.i]) {
			return false
		}
		switch s.peek() {
		case ',':
			s.i++
		case '}':
			s.i++
			return true
		default:
			return false
		}
	}
}

func (s *jsonScan) value() bool {
	// Deep custom metadata uses the standard decoder instead of growing this stack.
	if s.depth >= 64 {
		return false
	}
	s.depth++
	defer func() { s.depth-- }()
	switch c := s.peek(); {
	case c == '{':
		return s.object(func(string, []byte) bool { return true })
	case c == '[':
		s.i++
		if s.peek() == ']' {
			s.i++
			return true
		}
		for {
			if !s.value() {
				return false
			}
			switch s.peek() {
			case ',':
				s.i++
			case ']':
				s.i++
				return true
			default:
				return false
			}
		}
	case c == '"':
		_, ok := s.scanString(false)
		return ok
	case c == 't':
		return s.literal("true")
	case c == 'f':
		return s.literal("false")
	case c == 'n':
		return s.literal("null")
	case c == '-' || c >= '0' && c <= '9':
		return s.integer()
	}
	return false
}

func (s *jsonScan) literal(word string) bool {
	if !bytes.HasPrefix(s.data[s.i:], []byte(word)) {
		return false
	}
	s.i += len(word)
	return true
}

func (s *jsonScan) integer() bool {
	start := s.i
	if s.peek() == '-' {
		s.i++
	}
	digits := s.i
	for c := s.peek(); c >= '0' && c <= '9'; c = s.peek() {
		s.i++
	}
	n := s.i - digits
	// Larger numbers need the legacy float64 rounding and formatting path.
	if n == 0 || n > 15 || (n > 1 && s.data[digits] == '0') || s.data[start:s.i][0] == '-' && n == 1 && s.data[digits] == '0' {
		return false
	}
	switch s.peek() {
	case '.', 'e', 'E':
		return false
	}
	return true
}

func (s *jsonScan) string() (string, bool) { return s.scanString(true) }

func (s *jsonScan) scanString(decode bool) (string, bool) {
	if s.peek() != '"' {
		return "", false
	}
	start := s.i
	s.i++
	plain := true
	segment := s.i
	for {
		if s.i >= len(s.data) {
			return "", false
		}
		c := s.data[s.i]
		if c == '"' {
			break
		}
		if c != '\\' {
			s.i++
			continue
		}
		if !jsonPlain(s.data[segment:s.i]) {
			return "", false
		}
		if s.i+1 >= len(s.data) {
			return "", false
		}
		switch s.data[s.i+1] {
		case '"', '\\', 'n', 'r', 't':
			s.i += 2
		case 'u':
			if s.i+6 > len(s.data) {
				return "", false
			}
			switch string(s.data[s.i+2 : s.i+6]) {
			case "003c", "003e", "0026":
			default:
				plain = false
			}
			s.i += 6
		default:
			plain = false
			s.i += 2
		}
		segment = s.i
	}
	if !jsonPlain(s.data[segment:s.i]) {
		return "", false
	}
	s.i++
	raw := s.data[start:s.i]
	if plain && !decode {
		return "", true
	}
	if !bytes.ContainsRune(raw, '\\') {
		return string(raw[1 : len(raw)-1]), true
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	if !plain && !bytes.Equal(AppendJSONString(nil, value), raw) {
		return "", false
	}
	return value, true
}

func appendDelayHistory(b []byte, records []C.DelayHistory, nilWhenEmpty bool) ([]byte, error) {
	if len(records) == 0 {
		if nilWhenEmpty {
			return append(b, `null`...), nil
		}
		return append(b, `[]`...), nil
	}
	b = slices.Grow(b, 2+64*len(records))
	b = append(b, '[')
	for i, record := range records {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"time":"`...)
		var err error
		b, err = record.Time.AppendText(b)
		if err != nil {
			return nil, err
		}
		b = append(b, `","delay":`...)
		b = strconv.AppendUint(b, uint64(record.Delay), 10)
		b = append(b, '}')
	}
	return append(b, ']'), nil
}

// AppendJSONString appends s as encoding/json marshals it.
func AppendJSONString(b []byte, s string) []byte {
	start := len(b)
	b = append(b, '"')
	b = append(b, s...)
	if jsonPlain(b[start+1:]) {
		return append(b, '"')
	}
	encoded, _ := json.Marshal(s)
	return append(b[:start], encoded...)
}

func jsonPlain(s []byte) bool {
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c < 0x20 || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
				return false
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(s[i:])
		if r == utf8.RuneError && size == 1 || r == '\u2028' || r == '\u2029' {
			return false
		}
		i += size
	}
	return true
}

func (p *Proxy) appendExtraJSON(b []byte) ([]byte, error) {
	var states []proxyStateEntry
	p.extra.Range(func(url string, state *internalProxyState) bool {
		states = append(states, proxyStateEntry{url: url, state: state})
		return true
	})
	slices.SortFunc(states, func(a, b proxyStateEntry) int { return cmp.Compare(a.url, b.url) })
	b = append(b, '{')
	for i, entry := range states {
		if i > 0 {
			b = append(b, ',')
		}
		b = AppendJSONString(b, entry.url)
		b = append(b, `:{"alive":`...)
		b = strconv.AppendBool(b, entry.state.alive.Load())
		b = append(b, `,"history":`...)
		var err error
		if b, err = appendDelayHistory(b, entry.state.history.Copy(), true); err != nil {
			return nil, err
		}
		b = append(b, '}')
	}
	return append(b, '}'), nil
}
