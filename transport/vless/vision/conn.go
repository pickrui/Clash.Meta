package vision

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/log"

	"github.com/gofrs/uuid/v5"
)

var (
	_ N.ExtendedConn = (*Conn)(nil)
)

const (
	streamPadding uint32 = iota
	streamPlain
	streamDirect
)

const (
	lifecycleClosed uint32 = 1 << iota
	lifecycleDirect
)

type Conn struct {
	// Directional locks never guard the opposite direction's network I/O.
	readMu           sync.Mutex
	writeMu          sync.Mutex
	filterMu         sync.Mutex
	readState        atomic.Uint32
	writeState       atomic.Uint32
	handshakePending atomic.Bool
	lifecycle        atomic.Uint32
	frontHeadroom    int
	rearHeadroom     int

	net.Conn // should be *vless.Conn
	N.ExtendedReader
	N.ExtendedWriter
	userUUID uuid.UUID

	// [*tls.Conn] or other tls-like [net.Conn]'s internal variables
	netConn  net.Conn      // tlsConn.NetConn()
	input    *bytes.Reader // &tlsConn.input or nil
	rawInput *bytes.Buffer // &tlsConn.rawInput or nil

	// Shared TLS inspection is protected by filterMu. It never holds an I/O lock
	// for the opposite direction or keeps filterMu across a network operation.
	packetsToFilter      int
	isTLS                bool
	isTLS12orAbove       bool
	enableXTLS           bool
	cipher               uint16
	remainingServerHello uint16
	// Read parser state belongs to readMu; queries use readState instead.
	readRemainingBuffer  *buf.Buffer
	readRemainingContent int
	readRemainingPadding int
	readProcess          bool
	readFilterUUID       bool
	readLastCommand      byte
	// Write parser state belongs to writeMu.
	writeFilterApplicationData bool
	writeOnceUserUUID          []byte
}

func (vc *Conn) Read(b []byte) (int, error) {
	vc.readMu.Lock()
	defer vc.readMu.Unlock()
	if vc.lifecycle.Load()&lifecycleClosed != 0 {
		return 0, net.ErrClosed
	}

	if vc.readProcess {
		buffer := buf.With(b)
		err := vc.readBuffer(buffer)
		if unsafe.SliceData(buffer.Bytes()) != unsafe.SliceData(b) { // buffer.Bytes() not at the beginning of b
			copy(b, buffer.Bytes())
		}
		return buffer.Len(), err
	}
	return vc.ExtendedReader.Read(b)
}

func (vc *Conn) ReadBuffer(buffer *buf.Buffer) error {
	vc.readMu.Lock()
	defer vc.readMu.Unlock()
	if vc.lifecycle.Load()&lifecycleClosed != 0 {
		return net.ErrClosed
	}
	return vc.readBuffer(buffer)
}

// readBuffer is called with readMu held, including recursive state transitions.
func (vc *Conn) readBuffer(buffer *buf.Buffer) error {
	if vc.readRemainingBuffer != nil {
		_, err := buffer.ReadOnceFrom(vc.readRemainingBuffer)
		if vc.readRemainingBuffer.IsEmpty() {
			vc.readRemainingBuffer.Release()
			vc.readRemainingBuffer = nil
		}
		return err
	}
	if vc.readRemainingContent > 0 {
		readSize := xrayBufSize          // at least read xrayBufSize
		if buffer.FreeLen() > readSize { // input buffer larger than xrayBufSize, read as much as possible
			readSize = buffer.FreeLen()
		}
		if readSize > vc.readRemainingContent { // don't read out of bounds
			readSize = vc.readRemainingContent
		}

		readBuffer := buffer
		if buffer.FreeLen() < readSize {
			readBuffer = buf.NewSize(readSize)
			vc.readRemainingBuffer = readBuffer
		}
		n, err := vc.ExtendedReader.Read(readBuffer.FreeBytes()[:readSize])
		readBuffer.Truncate(n)
		vc.readRemainingContent -= n
		vc.FilterTLS(readBuffer.Bytes())
		if vc.readRemainingBuffer != nil {
			innerErr := vc.readBuffer(buffer) // back to top but not losing err
			if err != nil {
				err = innerErr
			}
		}
		return err
	}
	if vc.readRemainingPadding > 0 {
		n, err := io.CopyN(io.Discard, vc.ExtendedReader, int64(vc.readRemainingPadding))
		if err != nil {
			return err
		}
		vc.readRemainingPadding -= int(n)
	}
	if vc.readProcess {
		switch vc.readLastCommand {
		case commandPaddingContinue:
			//if vc.isTLS || vc.packetsToFilter > 0 {
			need := PaddingHeaderLen
			if !vc.readFilterUUID {
				need = PaddingHeaderLen - uuid.Size
			}
			var header []byte
			if buffer.FreeLen() < need {
				header = make([]byte, need)
			} else {
				header = buffer.FreeBytes()[:need]
			}
			_, err := io.ReadFull(vc.ExtendedReader, header)
			if err != nil {
				return err
			}
			if vc.readFilterUUID {
				vc.readFilterUUID = false
				if !bytes.Equal(vc.userUUID.Bytes(), header[:uuid.Size]) {
					err = fmt.Errorf("XTLS Vision server responded unknown UUID: %s", uuid.FromBytesOrNil(header[:uuid.Size]))
					log.Errorln("%s", err)
					return err
				}
				header = header[uuid.Size:]
			}
			vc.readRemainingPadding = int(binary.BigEndian.Uint16(header[3:]))
			vc.readRemainingContent = int(binary.BigEndian.Uint16(header[1:]))
			vc.readLastCommand = header[0]
			if vc.readLastCommand == commandPaddingDirect && !vc.beginDirect() {
				return net.ErrClosed
			}
			log.Debugln("XTLS Vision read padding: command=%d, payloadLen=%d, paddingLen=%d",
				vc.readLastCommand, vc.readRemainingContent, vc.readRemainingPadding)
			return vc.readBuffer(buffer)
			//}
		case commandPaddingEnd:
			vc.readProcess = false
			vc.readState.Store(streamPlain)
			return vc.readBuffer(buffer)
		case commandPaddingDirect:
			needReturn := false
			if vc.input != nil {
				_, err := buffer.ReadOnceFrom(vc.input)
				if err != nil {
					if !errors.Is(err, io.EOF) {
						return err
					}
				}
				if vc.input.Len() == 0 {
					needReturn = true
					*vc.input = bytes.Reader{} // full reset
					vc.input = nil
				} else { // buffer is full
					return nil
				}
			}
			if vc.rawInput != nil && buffer.FreeLen() > 0 {
				_, err := buffer.ReadOnceFrom(vc.rawInput)
				if err != nil {
					if !errors.Is(err, io.EOF) {
						return err
					}
				}
				needReturn = true
				if vc.rawInput.Len() == 0 {
					*vc.rawInput = bytes.Buffer{} // full reset
					vc.rawInput = nil
				}
			}
			if vc.input == nil && vc.rawInput == nil {
				vc.readProcess = false
				vc.ExtendedReader = N.NewExtendedReader(vc.netConn)
				vc.readState.Store(streamDirect)
				log.Debugln("XTLS Vision direct read start")
			}
			if needReturn {
				return nil
			}
		default:
			err := fmt.Errorf("XTLS Vision read unknown command: %d", vc.readLastCommand)
			log.Debugln("%s", err)
			return err
		}
	}
	return vc.ExtendedReader.ReadBuffer(buffer)
}

func (vc *Conn) Write(p []byte) (int, error) {
	vc.writeMu.Lock()
	defer vc.writeMu.Unlock()
	if vc.lifecycle.Load()&lifecycleClosed != 0 {
		return 0, net.ErrClosed
	}
	if !vc.writeFilterApplicationData {
		return vc.ExtendedWriter.Write(p)
	}
	// Allocate while owning the write direction, without re-entering WriteBuffer.
	front := N.CalculateFrontHeadroom(vc)
	rear := N.CalculateRearHeadroom(vc)
	buffer := buf.NewSize(front + len(p) + rear)
	buffer.Resize(front, 0)
	_, _ = buffer.Write(p)
	err := vc.writeBuffer(buffer)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (vc *Conn) WriteBuffer(buffer *buf.Buffer) error {
	vc.writeMu.Lock()
	defer vc.writeMu.Unlock()
	if vc.lifecycle.Load()&lifecycleClosed != 0 {
		buffer.Release()
		return net.ErrClosed
	}
	return vc.writeBuffer(buffer)
}

func (vc *Conn) writeBuffer(buffer *buf.Buffer) (err error) {
	if vc.writeFilterApplicationData {
		if buffer.IsEmpty() {
			vc.handshakePending.Store(false)
			ApplyPadding(buffer, commandPaddingContinue, &vc.writeOnceUserUUID, true) // we do a long padding to hide vless header
			return vc.ExtendedWriter.WriteBuffer(buffer)
		}

		tlsState := vc.filterTLSState(buffer.Bytes())
		buffers := vc.ReshapeBuffer(buffer)
		applyPadding := true
		for i, buffer := range buffers {
			command := commandPaddingContinue
			if applyPadding {
				if tlsState.isTLS && buffer.Len() > 6 && bytes.Equal(tlsApplicationDataStart, buffer.To(3)) {
					command = commandPaddingEnd
					if tlsState.enableXTLS {
						if !vc.beginDirect() {
							buf.ReleaseMulti(buffers[i:])
							return net.ErrClosed
						}
						command = commandPaddingDirect
					}
					vc.writeFilterApplicationData = false
					applyPadding = false
				} else if !tlsState.isTLS12orAbove && tlsState.packetsToFilter <= 1 {
					command = commandPaddingEnd
					vc.writeFilterApplicationData = false
					applyPadding = false
				}
				vc.handshakePending.Store(false)
				ApplyPadding(buffer, command, &vc.writeOnceUserUUID, tlsState.isTLS)
			}

			err = vc.ExtendedWriter.WriteBuffer(buffer)
			if err != nil {
				buf.ReleaseMulti(buffers[i:]) // release unwritten buffers
				return
			}
			if command == commandPaddingDirect {
				vc.ExtendedWriter = N.NewExtendedWriter(vc.netConn)
				vc.writeState.Store(streamDirect)
				log.Debugln("XTLS Vision direct write start")
			} else if command == commandPaddingEnd {
				vc.writeState.Store(streamPlain)
			}
		}
		return err
	}
	return vc.ExtendedWriter.WriteBuffer(buffer)
}

// Headroom is a conservative bound for both wrapped and direct writes. It does
// not inspect mutable read/write state while a caller prepares its buffer.
func (vc *Conn) FrontHeadroom() int               { return vc.frontHeadroom }
func (vc *Conn) RearHeadroom() int                { return vc.rearHeadroom }
func (vc *Conn) NeedHandshake() bool              { return vc.handshakePending.Load() }
func (vc *Conn) NeedAdditionalReadDeadline() bool { return true }

func (vc *Conn) Upstream() any {
	if vc.ReaderReplaceable() || vc.WriterReplaceable() {
		return vc.netConn
	}
	return vc.Conn
}

func (vc *Conn) UpstreamReader() any {
	if vc.ReaderReplaceable() {
		return vc.netConn
	}
	return vc.Conn
}

func (vc *Conn) UpstreamWriter() any {
	if vc.WriterReplaceable() {
		return vc.netConn
	}
	return vc.Conn
}

func (vc *Conn) ReaderPossiblyReplaceable() bool { return vc.readState.Load() == streamPadding }
func (vc *Conn) ReaderReplaceable() bool         { return vc.readState.Load() == streamDirect }
func (vc *Conn) WriterPossiblyReplaceable() bool { return vc.writeState.Load() == streamPadding }
func (vc *Conn) WriterReplaceable() bool         { return vc.writeState.Load() == streamDirect }

// Reserve the direct transition before sending/consuming its command. Close
// must not send a TLS close-notify once the peer can start sending raw bytes.
func (vc *Conn) beginDirect() bool {
	for {
		state := vc.lifecycle.Load()
		if state&lifecycleClosed != 0 {
			return false
		}
		if vc.lifecycle.CompareAndSwap(state, state|lifecycleDirect) {
			return true
		}
	}
}

func (vc *Conn) Close() error {
	state := vc.lifecycle.Or(lifecycleClosed)
	if state&lifecycleClosed != 0 {
		return net.ErrClosed
	}
	var err error
	if state&lifecycleDirect != 0 {
		err = vc.netConn.Close()
	} else {
		err = vc.Conn.Close()
	}
	// Close the transport before waiting for the reader, so blocked I/O wakes.
	vc.readMu.Lock()
	if vc.readRemainingBuffer != nil {
		vc.readRemainingBuffer.Release()
		vc.readRemainingBuffer = nil
	}
	vc.readMu.Unlock()
	return err
}
