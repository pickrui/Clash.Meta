package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/sudoku"
	"github.com/stretchr/testify/require"
)

func sudokuTableTestOption(key string) SudokuOption {
	return SudokuOption{Name: "fixture", Server: "127.0.0.1", Port: 9, Key: key}
}

func sudokuTableTestMetadata() *C.Metadata {
	return &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
}

func TestSudokuUnusedAndCanceledRequestsDoNotBuildTables(t *testing.T) {
	for _, multiplex := range []string{"off", "on"} {
		t.Run(multiplex, func(t *testing.T) {
			option := sudokuTableTestOption(t.Name())
			option.Multiplex = multiplex
			node, err := NewSudoku(option)
			require.NoError(t, err)
			t.Cleanup(func() { _ = node.Close() })
			node.dialer = sudokuTableOfflineDialer{}
			require.Nil(t, node.tables.set.Load())
			require.Nil(t, node.baseConf.Table)
			require.Empty(t, node.baseConf.Tables)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err = node.DialContext(ctx, sudokuTableTestMetadata())
			require.ErrorIs(t, err, context.Canceled)
			_, err = node.ListenPacketContext(ctx, sudokuTableTestMetadata())
			require.ErrorIs(t, err, context.Canceled)
			require.NoError(t, node.Close())
			require.Nil(t, node.tables.set.Load())
			require.Nil(t, cachedSudokuTableSlot(node.tables.spec.key))
		})
	}
}

func TestSudokuConcurrentNodesShareTables(t *testing.T) {
	nodes := make([]*Sudoku, 8)
	for i := range nodes {
		option := sudokuTableTestOption(t.Name())
		if i >= len(nodes)/2 {
			option.Key += "-other"
		}
		var err error
		nodes[i], err = NewSudoku(option)
		require.NoError(t, err)
		nodes[i].dialer = sudokuTableOfflineDialer{}
		t.Cleanup(func() { _ = nodes[i].Close() })
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, node := range nodes {
		for i := range 4 {
			wg.Go(func() {
				<-start
				var err error
				if i%2 == 0 {
					_, err = node.DialContext(context.Background(), sudokuTableTestMetadata())
				} else {
					_, err = node.ListenPacketContext(context.Background(), sudokuTableTestMetadata())
				}
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("offline dial: got %v, want %v", err, net.ErrClosed)
				}
			})
		}
	}
	close(start)
	wg.Wait()
	first, second := nodes[0].tables.set.Load(), nodes[len(nodes)/2].tables.set.Load()
	require.NotNil(t, first)
	require.NotNil(t, second)
	require.NotSame(t, first, second)
	for i, node := range nodes {
		want := first
		if i >= len(nodes)/2 {
			want = second
		}
		require.Same(t, want, node.tables.set.Load())
	}
}

func TestSudokuTableIdentityAndRotationSnapshot(t *testing.T) {
	patterns := []string{"xpxvvpvv", "vvpxxpvv"}
	option := sudokuTableTestOption(t.Name())
	option.TableType = "up_ascii_down_entropy"
	option.CustomTables = patterns
	node, err := NewSudoku(option)
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })
	patterns[0] = "invalid-after-construction"
	cfg, err := node.buildConfig(context.Background(), sudokuTableTestMetadata())
	require.NoError(t, err)
	reference, err := sudoku.NewClientTablesWithCustomPatterns(sudoku.ClientAEADSeed(option.Key), option.TableType, "", []string{"xpxvvpvv", "vvpxxpvv"})
	require.NoError(t, err)
	require.Len(t, cfg.Tables, len(reference))
	for i, table := range reference {
		require.Equal(t, table.Hint(), cfg.Tables[i].Hint())
		require.Equal(t, table.EncodeTable, cfg.Tables[i].EncodeTable)
		require.Equal(t, table.OppositeDirection().EncodeTable, cfg.Tables[i].OppositeDirection().EncodeTable)
	}

	for _, tc := range []struct {
		name     string
		mode     string
		patterns []string
		shared   bool
	}{
		{"same", option.TableType, []string{" xpxvvpvv ", "vvpxxpvv"}, true},
		{"reversed", option.TableType, []string{"vvpxxpvv", "xpxvvpvv"}, false},
		{"different-mode", "up_entropy_down_ascii", []string{"xpxvvpvv", "vvpxxpvv"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			otherOption := option
			otherOption.TableType, otherOption.CustomTables = tc.mode, tc.patterns
			other, err := NewSudoku(otherOption)
			require.NoError(t, err)
			defer other.Close()
			_, err = other.buildConfig(context.Background(), sudokuTableTestMetadata())
			require.NoError(t, err)
			require.Equal(t, tc.shared, node.tables.set.Load() == other.tables.set.Load())
		})
	}
}

func TestSudokuSharedDirectionalTablesUDPRoundTrip(t *testing.T) {
	httpMask := false
	option := sudokuTableTestOption(t.Name())
	option.HTTPMask = &httpMask
	option.TableType = "up_ascii_down_entropy"
	option.CustomTables = []string{"xpxvvpvv", "vvpxxpvv"}
	serverConfig := sudoku.DefaultConfig()
	serverConfig.Key, serverConfig.DisableHTTPMask = option.Key, true
	var err error
	serverConfig.Tables, err = sudoku.NewServerTablesWithCustomPatterns(sudoku.ServerAEADSeed(option.Key), option.TableType, "", option.CustomTables)
	require.NoError(t, err)
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}
	var shared *sudokuTableSet
	for range 2 {
		node, err := NewSudoku(option)
		require.NoError(t, err)
		defer node.Close()
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()
		node.dialer = sudokuTablePipeDialer{conn: client}
		result := make(chan error, 1)
		go func() {
			result <- func() error {
				defer server.Close()
				conn, meta, err := sudoku.ServerHandshake(server, serverConfig)
				if err != nil {
					return err
				}
				session, err := sudoku.ReadServerSession(conn, meta)
				if err != nil {
					return err
				}
				if session.Type != sudoku.SessionTypeUoT {
					return fmt.Errorf("unexpected session type: %v", session.Type)
				}
				address, data, err := sudoku.ReadDatagram(session.Conn)
				if err != nil {
					return err
				}
				return sudoku.WriteDatagram(session.Conn, address, data)
			}()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		packet, err := node.ListenPacketContext(ctx, sudokuTableTestMetadata())
		require.NoError(t, err)
		defer packet.Close()
		require.NoError(t, packet.SetDeadline(time.Now().Add(5*time.Second)))
		target := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:443"))
		n, err := packet.WriteTo(payload, target)
		require.NoError(t, err)
		require.Equal(t, len(payload), n)
		buffer := make([]byte, len(payload))
		n, address, err := packet.ReadFrom(buffer)
		require.NoError(t, err)
		require.Equal(t, payload, buffer[:n])
		require.Equal(t, target.String(), address.String())
		require.NoError(t, <-result)
		if shared == nil {
			shared = node.tables.set.Load()
		} else {
			require.Same(t, shared, node.tables.set.Load())
		}
	}
}

func TestSudokuInvalidSettingsRejectedBeforeDial(t *testing.T) {
	padding := 200
	for _, tc := range []struct {
		name   string
		modify func(*SudokuOption)
		want   string
	}{
		{"pattern", func(o *SudokuOption) { o.CustomTable = "xxxxvvvv" }, "build table(s) failed: custom table"},
		{"directional-pattern", func(o *SudokuOption) {
			o.TableType, o.CustomTable = "up_ascii_down_entropy", "bad"
		}, "build table(s) failed: custom table"},
		{"rotation", func(o *SudokuOption) { o.CustomTables = []string{"xpxvvpvv", "bad"} }, "build table(s) failed: custom table"},
		{"mode", func(o *SudokuOption) { o.TableType = "bogus" }, "table-type must be"},
		{"aead", func(o *SudokuOption) { o.AEADMethod = "bogus" }, "invalid aead-method"},
		{"padding", func(o *SudokuOption) { o.PaddingMin = &padding }, "padding-min must be"},
		{"path", func(o *SudokuOption) { o.PathRoot = "a/b" }, "invalid http-mask-path-root"},
		{"multiplex", func(o *SudokuOption) { o.Multiplex = "sometimes" }, "invalid multiplex"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			option := sudokuTableTestOption(t.Name())
			tc.modify(&option)
			node, err := NewSudoku(option)
			if node != nil {
				_ = node.Close()
			}
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestSudokuTableCacheReleasesUnusedEntries(t *testing.T) {
	option := sudokuTableTestOption(t.Name())
	key, old := func() (sudokuTableKey, *sudokuTableSlot) {
		node, err := NewSudoku(option)
		require.NoError(t, err)
		defer node.Close()
		_, err = node.buildConfig(context.Background(), sudokuTableTestMetadata())
		require.NoError(t, err)
		key := node.tables.spec.key
		return key, cachedSudokuTableSlot(key)
	}()
	require.NotNil(t, old)
	require.Eventually(t, func() bool {
		runtime.GC()
		return cachedSudokuTableSlot(key) == nil
	}, 5*time.Second, 10*time.Millisecond)

	node, err := NewSudoku(option)
	require.NoError(t, err)
	defer node.Close()
	_, err = node.buildConfig(context.Background(), sudokuTableTestMetadata())
	require.NoError(t, err)
	current := cachedSudokuTableSlot(key)
	require.NotNil(t, current)
	require.NotSame(t, old, current)
	forgetSudokuTables(old)
	require.Same(t, current, cachedSudokuTableSlot(key))
}

func TestSudokuTableWaiterCanCancel(t *testing.T) {
	node, err := NewSudoku(sudokuTableTestOption(t.Name()))
	require.NoError(t, err)
	defer node.Close()
	slot := &sudokuTableSlot{key: node.tables.spec.key, ready: make(chan struct{})}
	sudokuTableCache.Lock()
	if sudokuTableCache.slots == nil {
		sudokuTableCache.slots = make(map[sudokuTableKey]*sudokuTableSlot)
	}
	sudokuTableCache.slots[slot.key] = slot
	sudokuTableCache.Unlock()
	defer forgetSudokuTables(slot)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = node.buildConfig(ctx, sudokuTableTestMetadata())
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, node.tables.set.Load())
}

func cachedSudokuTableSlot(key sudokuTableKey) *sudokuTableSlot {
	sudokuTableCache.Lock()
	defer sudokuTableCache.Unlock()
	return sudokuTableCache.slots[key]
}

type sudokuTableOfflineDialer struct{}

func (sudokuTableOfflineDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (sudokuTableOfflineDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type sudokuTablePipeDialer struct {
	sudokuTableOfflineDialer
	conn net.Conn
}

func (d sudokuTablePipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}
