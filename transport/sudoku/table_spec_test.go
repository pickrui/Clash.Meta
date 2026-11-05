package sudoku

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientTablePatternsMatchesBuilder(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		pattern  string
		rotation []string
	}{
		{"", "", nil},
		{"prefer_ascii", "ignored-invalid-pattern", nil},
		{"prefer_entropy", " xpxvvpvv ", nil},
		{"up_ascii_down_entropy", "xpxvvpvv", nil},
		{"up_entropy_down_ascii", "", []string{"xpxvvpvv", " vvpxxpvv "}},
		{"prefer_entropy", "invalid-but-overridden", []string{""}},
		{"bogus", "", nil},
		{"up_ascii", "", nil},
		{"prefer_entropy", "xxxxvvvv", nil},
		{"prefer_entropy", "xpxvvpv", nil},
		{"entropy", "xpxvvpvq", nil},
		{"prefer_entropy", "", []string{"xpxvvpvv", "bad"}},
		{"up_ascii_down_entropy", "xxxxvvvv", nil},
		{"up_entropy_down_ascii", "", []string{"xxpp"}},
	} {
		t.Run(fmt.Sprintf("%s/%s/%v", tc.mode, tc.pattern, tc.rotation), func(t *testing.T) {
			tables, buildErr := NewClientTablesWithCustomPatterns("validation-fixture", tc.mode, tc.pattern, tc.rotation)
			patterns, validationErr := ClientTablePatterns(tc.mode, tc.pattern, tc.rotation)
			if buildErr == nil {
				require.NoError(t, validationErr)
				require.Len(t, patterns, len(tables))
			} else {
				require.EqualError(t, validationErr, buildErr.Error())
			}
		})
	}
}
