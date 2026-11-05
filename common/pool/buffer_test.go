package pool

import (
	"bytes"
	"testing"
)

func TestBufferRetentionBudget(t *testing.T) {
	for _, size := range []int{1024, maxRetainedBufferCapacity, maxRetainedBufferCapacity + 1, 4 << 20} {
		buffer := bytes.NewBuffer(make([]byte, size))
		PutBuffer(buffer)
		if buffer.Len() != 0 || buffer.Cap() > maxRetainedBufferCapacity {
			t.Fatalf("returned %d-byte buffer retains len=%d cap=%d", size, buffer.Len(), buffer.Cap())
		}
		if size <= maxRetainedBufferCapacity && buffer.Cap() != size {
			t.Fatalf("discarded reusable %d-byte allocation", size)
		}
	}
	buffer := GetBuffer()
	defer PutBuffer(buffer)
	if buffer.Len() != 0 {
		t.Fatal("borrowed buffer contains old payload")
	}
	payload := bytes.Repeat([]byte("packet"), 20000)
	if _, err := buffer.Write(payload); err != nil || !bytes.Equal(buffer.Bytes(), payload) {
		t.Fatalf("retention budget changed payload support: %v", err)
	}
}
