package utils

import (
	"time"

	"github.com/dlclark/regexp2"
)

const NameRegexMatchTimeout = 100 * time.Millisecond

func CompileNameRegex(pattern string) (*regexp2.Regexp, error) {
	compiled, err := regexp2.Compile(pattern, regexp2.None)
	if err == nil {
		compiled.MatchTimeout = NameRegexMatchTimeout
	}
	return compiled, err
}

func MustCompileNameRegex(pattern string) *regexp2.Regexp {
	compiled, err := CompileNameRegex(pattern)
	if err != nil {
		panic(err)
	}
	return compiled
}
