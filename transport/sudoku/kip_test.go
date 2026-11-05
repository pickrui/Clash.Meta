package sudoku

import (
	"bytes"
	"io"
	"testing"

	sudokuobfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

func TestKIPClientHelloTableHintRoundTrip(t *testing.T) {
	hello := &KIPClientHello{
		Features:     KIPFeatAll,
		TableHint:    0x12345678,
		HasTableHint: true,
	}
	decoded, err := DecodeKIPClientHelloPayload(hello.EncodePayload())
	if err != nil {
		t.Fatalf("decode client hello: %v", err)
	}
	if !decoded.HasTableHint {
		t.Fatalf("expected decoded hello to carry table hint")
	}
	if decoded.TableHint != hello.TableHint {
		t.Fatalf("decoded table hint = %08x, want %08x", decoded.TableHint, hello.TableHint)
	}
}

func TestResolveClientHelloTableAllowsDirectionalASCIIRotation(t *testing.T) {
	tables, err := NewClientTablesWithCustomPatterns("seed", "up_ascii_down_entropy", "", []string{"xpxvvpvv", "vxpvxvvp"})
	if err != nil {
		t.Fatalf("build tables: %v", err)
	}
	if len(tables) != 2 {
		t.Fatalf("expected 2 tables, got %d", len(tables))
	}

	selected, err := ResolveClientHelloTable(tables[0], tables, &KIPClientHello{
		TableHint:    tables[1].Hint(),
		HasTableHint: true,
	})
	if err != nil {
		t.Fatalf("resolve client hello table: %v", err)
	}
	if selected != tables[1] {
		t.Fatalf("resolved table mismatch")
	}
}

func TestResolveClientHelloTableRejectsEntropyMismatch(t *testing.T) {
	a, err := sudokuobfs.NewTableWithCustom("seed", "prefer_entropy", "xpxvvpvv")
	if err != nil {
		t.Fatalf("table a: %v", err)
	}
	b, err := sudokuobfs.NewTableWithCustom("seed", "prefer_entropy", "vxpvxvvp")
	if err != nil {
		t.Fatalf("table b: %v", err)
	}

	if _, err := ResolveClientHelloTable(a, []*sudokuobfs.Table{a, b}, &KIPClientHello{
		TableHint:    b.Hint(),
		HasTableHint: true,
	}); err == nil {
		t.Fatalf("expected entropy-table mismatch to fail")
	}
}

type limitedFrameWriter struct {
	bytes.Buffer
	limit int
}

func (w *limitedFrameWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		p = p[:w.limit]
	}
	return w.Buffer.Write(p)
}

func TestFramedWritesHandleShortWrites(t *testing.T) {
	payload := []byte{1, 2, 3}
	w := &limitedFrameWriter{limit: 2}
	if err := WriteKIPMessage(w, KIPTypeOpenTCP, payload); err != nil {
		t.Fatal(err)
	}
	msg, err := ReadKIPMessage(bytes.NewReader(w.Bytes()))
	if err != nil || msg.Type != KIPTypeOpenTCP || !bytes.Equal(msg.Payload, payload) {
		t.Fatalf("KIP: %+v, %v", msg, err)
	}
	w.Reset()
	if err := WriteDatagram(w, "192.0.2.1:53", payload); err != nil {
		t.Fatal(err)
	}
	addr, got, err := NewUoTReader(bytes.NewReader(w.Bytes())).ReadDatagram()
	if err != nil || addr.String() != "192.0.2.1:53" || !bytes.Equal(got, payload) {
		t.Fatalf("UoT: %v, %x, %v", addr, got, err)
	}
	w.limit = 0
	if err := WriteKIPMessage(w, KIPTypeOpenTCP, payload); err != io.ErrShortWrite {
		t.Fatalf("zero KIP write: %v", err)
	}
	if err := WriteDatagram(w, "192.0.2.1:53", payload); err != io.ErrShortWrite {
		t.Fatalf("zero UoT write: %v", err)
	}
}
