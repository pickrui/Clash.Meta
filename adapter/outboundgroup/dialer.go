package outboundgroup

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"
)

const dialerTestPrefix = "flclash-chain-"

func scopedDialerTestURL(raw, group, dialer string) (string, error) {
	target, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	// Fragments stay local; the existing URL-keyed latency cache separates routes.
	target.Fragment = fmt.Sprintf("%s%x", dialerTestPrefix, sha256.Sum256([]byte(raw+"\x00"+group+"\x00"+dialer)))
	target.RawFragment = ""
	return target.String(), nil
}

func IsDialerTestURL(raw string) bool {
	target, err := url.Parse(raw)
	return err == nil && strings.HasPrefix(target.Fragment, dialerTestPrefix)
}
