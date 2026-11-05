package sudoku

import (
	"strings"

	"github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

// ClientTablePatterns returns the trimmed patterns NewClientTablesWithCustomPatterns
// builds, or the error it would return, without building tables.
func ClientTablePatterns(tableType string, customTable string, customTables []string) ([]string, error) {
	raw := normalizeCustomPatterns(customTable, customTables)
	patterns := make([]string, len(raw))
	for i, pattern := range raw {
		patterns[i] = strings.TrimSpace(pattern)
	}
	if err := sudoku.ValidateTableSpecs(tableType, patterns); err != nil {
		return nil, err
	}
	return patterns, nil
}
