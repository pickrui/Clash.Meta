package outbound

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"weak"

	"github.com/metacubex/mihomo/transport/sudoku"
	obfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

type sudokuTableKey struct {
	seed      string
	tableType string
	patterns  string
}

type sudokuTableSpec struct {
	key      sudokuTableKey
	patterns []string
}

func newSudokuTableSpec(seed, tableType, customTable string, customTables []string) (sudokuTableSpec, error) {
	patterns, err := sudoku.ClientTablePatterns(tableType, customTable, customTables)
	if err != nil {
		return sudokuTableSpec{}, err
	}
	var identity strings.Builder
	for _, pattern := range patterns {
		identity.WriteString(strconv.Quote(pattern))
	}
	return sudokuTableSpec{
		key:      sudokuTableKey{seed: seed, tableType: tableType, patterns: identity.String()},
		patterns: patterns,
	}, nil
}

type sudokuTableSet struct {
	tables []*obfs.Table
}

type sudokuTables struct {
	spec sudokuTableSpec
	set  atomic.Pointer[sudokuTableSet]
}

func (t *sudokuTables) fill(ctx context.Context, conf *sudoku.ProtocolConfig) error {
	set := t.set.Load()
	if set == nil {
		shared, err := sharedSudokuTables(ctx, t.spec)
		if err != nil {
			return fmt.Errorf("build table(s) failed: %w", err)
		}
		t.set.CompareAndSwap(nil, shared)
		set = t.set.Load()
	}
	if len(set.tables) == 1 {
		conf.Table, conf.Tables = set.tables[0], nil
	} else {
		conf.Table, conf.Tables = nil, set.tables
	}
	return nil
}

type sudokuTableSlot struct {
	key   sudokuTableKey
	ready chan struct{}
	set   weak.Pointer[sudokuTableSet]
	err   error
}

// Cache entries must not keep tables alive after their owning outbounds are collected.
var sudokuTableCache struct {
	sync.Mutex
	slots map[sudokuTableKey]*sudokuTableSlot
}

func sharedSudokuTables(ctx context.Context, spec sudokuTableSpec) (*sudokuTableSet, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sudokuTableCache.Lock()
		slot := sudokuTableCache.slots[spec.key]
		if slot == nil {
			slot = &sudokuTableSlot{key: spec.key, ready: make(chan struct{})}
			if sudokuTableCache.slots == nil {
				sudokuTableCache.slots = make(map[sudokuTableKey]*sudokuTableSlot)
			}
			sudokuTableCache.slots[spec.key] = slot
			sudokuTableCache.Unlock()
			return slot.fill(spec)
		}
		sudokuTableCache.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-slot.ready:
		}
		if slot.err != nil {
			return nil, slot.err
		}
		if set := slot.set.Value(); set != nil {
			return set, nil
		}
		forgetSudokuTables(slot)
	}
}

func (slot *sudokuTableSlot) fill(spec sudokuTableSpec) (*sudokuTableSet, error) {
	defer close(slot.ready)
	tables, err := sudoku.NewClientTablesWithCustomPatterns(spec.key.seed, spec.key.tableType, "", spec.patterns)
	if err != nil {
		slot.err = err
		forgetSudokuTables(slot)
		return nil, err
	}
	set := &sudokuTableSet{tables: tables}
	slot.set = weak.Make(set)
	runtime.AddCleanup(set, forgetSudokuTables, slot)
	return set, nil
}

func forgetSudokuTables(slot *sudokuTableSlot) {
	sudokuTableCache.Lock()
	if sudokuTableCache.slots[slot.key] == slot {
		delete(sudokuTableCache.slots, slot.key)
	}
	sudokuTableCache.Unlock()
}
