package tls

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
)

// Simulate a socket deadline interrupting a TLS header or payload after some
// bytes were consumed. Clearing the deadline resumes the same byte stream.
type restlsInterruptedRecordConn struct {
	net.Conn
	prefix      []byte
	remainder   *bytes.Reader
	interrupted bool
}

func (c *restlsInterruptedRecordConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	if !c.interrupted {
		c.interrupted = true
		return 0, os.ErrDeadlineExceeded
	}
	return c.remainder.Read(p)
}

func TestRestlsServerRecordResumesAfterDeadline(t *testing.T) {
	payload := bytes.Repeat([]byte("partial-record"), 4)
	record := append([]byte{23, 3, 3, 0, byte(len(payload))}, payload...)
	for cut := 1; cut < len(record); cut++ {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			conn := &restlsInterruptedRecordConn{prefix: record[:cut], remainder: bytes.NewReader(append(bytes.Clone(record[cut:]), record...))}
			reader := &restlsServerRecordReader{}
			readRecord := reader.ReadRecord
			if _, err := readRecord(conn); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("first read should time out: %v", err)
			}
			for i := 0; i < 2; i++ {
				got, err := readRecord(conn)
				if err != nil {
					t.Fatalf("record could not resume after deadline: %v", err)
				}
				if !bytes.Equal(got, record) {
					t.Fatal("record bytes changed after deadline")
				}
			}
			if _, err := readRecord(conn); !errors.Is(err, io.EOF) {
				t.Fatalf("unexpected trailing data: %v", err)
			}
		})
	}
}
