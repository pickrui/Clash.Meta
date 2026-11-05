package pool

import (
	"bytes"
	"sync"
)

var bufferPool = sync.Pool{New: func() any { return &bytes.Buffer{} }}

const maxRetainedBufferCapacity = 64 * 1024

func GetBuffer() *bytes.Buffer {
	return bufferPool.Get().(*bytes.Buffer)
}

func PutBuffer(buf *bytes.Buffer) {
	if buf.Cap() > maxRetainedBufferCapacity {
		*buf = bytes.Buffer{}
	} else {
		buf.Reset()
	}
	bufferPool.Put(buf)
}
