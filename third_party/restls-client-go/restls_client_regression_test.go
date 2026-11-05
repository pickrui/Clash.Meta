package tls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestRestlsClientRejectsShortGCMRecords(t *testing.T) {
	for size := recordHeaderLen; size < recordHeaderLen+8+restlsAppDataAuthHeaderLength; size++ {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			conn := &Conn{config: &Config{RestlsSecret: bytes.Repeat([]byte{1}, 32)}, restls12WithGCM: true}
			record := make([]byte, size)
			record[0] = byte(recordTypeApplicationData)
			if size >= recordHeaderLen+8 {
				binary.BigEndian.PutUint64(record[recordHeaderLen:], 1)
			}
			_, _, err := conn.extractRestlsAppData(record)
			if err != alertBadRecordMAC {
				t.Fatalf("short GCM record error=%v", err)
			}
		})
	}
}

func TestRestlsClientAuthenticatedRecordBounds(t *testing.T) {
	for _, test := range []struct {
		name    string
		length  uint16
		command byte
		bad     bool
	}{
		{"valid", 1, 0, false}, {"overstated_payload", 2, 0, true}, {"invalid_command", 1, 2, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := &Conn{config: &Config{RestlsSecret: bytes.Repeat([]byte{1}, 32)}, serverRandom: bytes.Repeat([]byte{2}, 32)}
			record := make([]byte, recordHeaderLen+restlsAppDataAuthHeaderLength+1)
			record[0] = byte(recordTypeApplicationData)
			record[1], record[2] = 3, 3
			binary.BigEndian.PutUint16(record[3:], uint16(len(record)-recordHeaderLen))
			payload := record[recordHeaderLen:]
			binary.BigEndian.PutUint16(payload[restlsAppDataLenOffset:], test.length)
			payload[restlsAppDataLenOffset+2] = test.command
			payload[restlsAppDataOffset] = 42
			mask := conn.restlsAuthHeaderHash(true)
			mask.Write(payload[restlsAppDataOffset:])
			xorWithMac(payload[restlsAppDataLenOffset:], mask.Sum(nil)[:restlsMaskLength])
			auth := conn.restlsAuthHeaderHash(true)
			auth.Write(record[:recordHeaderLen])
			auth.Write(payload[restlsAppDataLenOffset:])
			copy(payload[:restlsAppDataMACLength], auth.Sum(nil))
			data, _, err := conn.extractRestlsAppData(record)
			if test.bad {
				if err != alertBadRecordMAC {
					t.Fatalf("authenticated malformed record error=%v", err)
				}
			} else if err != nil || !bytes.Equal(data, []byte{42}) {
				t.Fatalf("valid record data=%v err=%v", data, err)
			}
		})
	}
}
