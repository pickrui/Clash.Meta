package outbound

import (
	"context"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func BenchmarkSudokuUnused(b *testing.B) {
	for _, mode := range []string{"prefer_entropy", "up_ascii_down_entropy"} {
		b.Run(mode, func(b *testing.B) {
			option := SudokuOption{Name: "unused", Server: "127.0.0.1", Port: 9, Key: "benchmark-key", TableType: mode}
			b.ReportAllocs()
			for b.Loop() {
				node, err := NewSudoku(option)
				if err != nil {
					b.Fatal(err)
				}
				if err := node.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSudokuSharedTables(b *testing.B) {
	option := SudokuOption{Name: "shared", Server: "127.0.0.1", Port: 9, Key: "shared-benchmark-key"}
	metadata := &C.Metadata{Host: "example.test", DstPort: 443}
	owner, err := NewSudoku(option)
	if err != nil {
		b.Fatal(err)
	}
	defer owner.Close()
	if _, err = owner.buildConfig(context.Background(), metadata); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		node, err := NewSudoku(option)
		if err != nil {
			b.Fatal(err)
		}
		if _, err = node.buildConfig(context.Background(), metadata); err != nil {
			b.Fatal(err)
		}
		if err := node.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
