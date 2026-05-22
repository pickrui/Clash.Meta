package snell

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

const (
	v4RecordHeaderLen                      = 7
	v4RecordVersion                   byte = 0x04
	v4DynamicRecordMSS                     = 1208
	v4DynamicRecordSizeBoostThreshold      = 128 * 1024
)

var errV4InvalidRecord = errors.New("invalid snell v4 record")

type v4Conn struct {
	net.Conn
	cipher   shadowaead.Cipher
	identity []byte
	reader   *v4Reader
	writer   *v4Writer
	readMu   sync.Mutex
	writeMu  sync.Mutex
}

func newV4Conn(conn net.Conn, streamCipher shadowaead.Cipher, identity []byte) *v4Conn {
	return &v4Conn{Conn: conn, cipher: streamCipher, identity: append([]byte(nil), identity...)}
}

func (conn *v4Conn) initReader() error {
	salt := make([]byte, conn.cipher.SaltSize())
	if _, err := io.ReadFull(conn.Conn, salt); err != nil {
		return err
	}
	aead, err := conn.cipher.Decrypter(salt)
	if err != nil {
		return err
	}
	conn.reader = &v4Reader{reader: conn.Conn, aead: aead}
	return nil
}

func (conn *v4Conn) Read(payload []byte) (int, error) {
	conn.readMu.Lock()
	defer conn.readMu.Unlock()

	if conn.reader == nil {
		if err := conn.initReader(); err != nil {
			return 0, err
		}
	}
	return conn.reader.Read(payload)
}

func (conn *v4Conn) initWriter() error {
	salt := make([]byte, conn.cipher.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := conn.cipher.Encrypter(salt)
	if err != nil {
		return err
	}
	header := salt
	if len(conn.identity) == IdentityHeaderLength {
		header = make([]byte, 0, len(salt)+len(identityWireMagic)+IdentityHeaderLength)
		header = append(header, salt...)
		header = append(header, identityWireMagic...)
		header = append(header, conn.identity...)
	}
	if _, err = conn.Conn.Write(header); err != nil {
		return err
	}
	conn.writer = &v4Writer{writer: conn.Conn, aead: aead}
	return nil
}

func (conn *v4Conn) Write(payload []byte) (int, error) {
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()

	if conn.writer == nil {
		if err := conn.initWriter(); err != nil {
			return 0, err
		}
	}
	return conn.writer.Write(payload)
}

func (conn *v4Conn) WritePacketFrame(payload []byte) (int, error) {
	if len(payload) > maxLength {
		return 0, errors.New("snell v4 frame too large")
	}
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()

	if conn.writer == nil {
		if err := conn.initWriter(); err != nil {
			return 0, err
		}
	}
	if err := conn.writer.writeRecord(payload); err != nil {
		return 0, err
	}
	return len(payload), nil
}

type v4Reader struct {
	reader io.Reader
	aead   cipher.AEAD
	nonce  [32]byte
	buffer []byte
	offset int
}

func (reader *v4Reader) Read(payload []byte) (int, error) {
	if len(reader.buffer) == reader.offset {
		record, err := reader.readRecord()
		if err != nil {
			return 0, err
		}
		reader.buffer = record
		reader.offset = 0
	}

	copied := copy(payload, reader.buffer[reader.offset:])
	reader.offset += copied
	if len(reader.buffer) == reader.offset {
		reader.buffer = nil
		reader.offset = 0
	}
	return copied, nil
}

func (reader *v4Reader) readRecord() ([]byte, error) {
	tagSize := reader.aead.Overhead()
	nonce := reader.nonce[:reader.aead.NonceSize()]

	headerBlock := make([]byte, v4RecordHeaderLen+tagSize)
	if _, err := io.ReadFull(reader.reader, headerBlock); err != nil {
		return nil, err
	}
	header, err := reader.aead.Open(nil, nonce, headerBlock, nil)
	incrementV4Nonce(nonce)
	if err != nil {
		return nil, err
	}

	paddingSize, payloadSize, err := parseV4RecordHeader(header)
	if err != nil {
		return nil, err
	}
	if payloadSize == 0 {
		return nil, shadowaead.ErrZeroChunk
	}

	ciphertext, err := readV4RecordPayload(reader.reader, paddingSize, payloadSize, tagSize)
	if err != nil {
		return nil, err
	}
	plain, err := reader.aead.Open(nil, nonce, ciphertext, nil)
	incrementV4Nonce(nonce)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

type v4Writer struct {
	writer    io.Writer
	aead      cipher.AEAD
	nonce     [32]byte
	seenBytes int
}

func (writer *v4Writer) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, writer.writeRecord(nil)
	}

	written := 0
	for written < len(payload) {
		end := written + writer.maxRecordPayloadSize()
		if end > len(payload) {
			end = len(payload)
		}
		if err := writer.writeRecord(payload[written:end]); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (writer *v4Writer) maxRecordPayloadSize() int {
	if writer.seenBytes >= v4DynamicRecordSizeBoostThreshold {
		return maxLength
	}

	size := v4DynamicRecordMSS - v4RecordHeaderLen - 2*writer.aead.Overhead()
	if size <= 0 || size > maxLength {
		return maxLength
	}
	return size
}

func (writer *v4Writer) writeRecord(payload []byte) error {
	tagSize := writer.aead.Overhead()
	nonce := writer.nonce[:writer.aead.NonceSize()]
	payloadSize := len(payload)
	paddingSize := randomV4PaddingSize(payloadSize, tagSize)

	frame := make([]byte, 0, v4RecordHeaderLen+tagSize+paddingSize+payloadSize+tagSize)
	var header [v4RecordHeaderLen]byte
	header[0] = v4RecordVersion
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingSize))
	binary.BigEndian.PutUint16(header[5:7], uint16(payloadSize))
	frame = writer.aead.Seal(frame, nonce, header[:], nil)
	incrementV4Nonce(nonce)

	if payloadSize > 0 {
		block := make([]byte, paddingSize, paddingSize+payloadSize+tagSize)
		if paddingSize > 0 {
			if _, err := rand.Read(block); err != nil {
				return err
			}
		}
		block = writer.aead.Seal(block, nonce, payload, nil)
		incrementV4Nonce(nonce)
		if paddingSize > 0 {
			shuffleV4Padding(block, paddingSize, payloadSize+tagSize)
		}
		frame = append(frame, block...)
		writer.seenBytes += payloadSize
	}

	return writeFull(writer.writer, frame)
}

func randomV4PaddingSize(payloadSize, tagSize int) int {
	if payloadSize == 0 {
		return 0
	}

	maxPadding := v4DynamicRecordMSS - v4RecordHeaderLen - 2*tagSize - payloadSize
	if maxPadding <= 0 {
		return 0
	}
	if maxPadding > 512 {
		maxPadding = 512
	}

	var seed [2]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return 1
	}
	return int(binary.BigEndian.Uint16(seed[:])%uint16(maxPadding)) + 1
}

func parseV4RecordHeader(header []byte) (int, int, error) {
	if len(header) != v4RecordHeaderLen || header[0] != v4RecordVersion {
		return 0, 0, errV4InvalidRecord
	}
	paddingSize := int(binary.BigEndian.Uint16(header[3:5]))
	payloadSize := int(binary.BigEndian.Uint16(header[5:7]))
	if payloadSize > maxLength {
		return 0, 0, errV4InvalidRecord
	}
	if payloadSize == 0 && paddingSize != 0 {
		return 0, 0, errV4InvalidRecord
	}
	return paddingSize, payloadSize, nil
}

func readV4RecordPayload(reader io.Reader, paddingSize, payloadSize, tagSize int) ([]byte, error) {
	block := make([]byte, paddingSize+payloadSize+tagSize)
	if _, err := io.ReadFull(reader, block); err != nil {
		return nil, err
	}
	if paddingSize > 0 {
		unshuffleV4Padding(block, paddingSize, payloadSize+tagSize)
	}
	return block[paddingSize:], nil
}

func unshuffleV4Padding(block []byte, paddingSize, ciphertextSize int) {
	shuffleV4Padding(block, paddingSize, ciphertextSize)
}

func shuffleV4Padding(block []byte, paddingSize, ciphertextSize int) {
	for offset := 0; offset < paddingSize && offset < ciphertextSize; offset += 2 {
		block[offset], block[paddingSize+offset] = block[paddingSize+offset], block[offset]
	}
}

func incrementV4Nonce(nonce []byte) {
	for index := range nonce {
		nonce[index]++
		if nonce[index] != 0 {
			return
		}
	}
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
