package inbound_test

import (
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
)

func TestInboundSudoku_Multiplex(t *testing.T) {
	for _, mode := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		t.Run(mode, func(t *testing.T) {
			httpMask := mode != "raw"
			if mode == "raw" {
				mode = "legacy"
			}
			testInboundSudoku(t, inbound.SudokuOption{
				Key: "local-sudoku-multiplex-test", HTTPMaskMode: mode, DisableHTTPMask: !httpMask,
			}, outbound.SudokuOption{
				Key: "local-sudoku-multiplex-test", HTTPMaskMode: mode, HTTPMask: &httpMask, HTTPMaskMultiplex: "on",
			})
		})
	}
}
