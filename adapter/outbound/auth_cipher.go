package outbound

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"
)

const (
	authCipherAEADChunkSize     = 16384
	authCipherAEADSaltSize      = 16
	authCipherUDPSecurityMagic  = "FUDP"
	authCipherUDPHeaderSize     = len(authCipherUDPSecurityMagic) + 8 + 16
	authCipherUDPReplayWindow   = 30 * time.Second
	authCipherUDPReplayMaxItems = 262144
)

var authCipherUDPReplay = newAuthCipherUDPReplayCache(authCipherUDPReplayWindow, authCipherUDPReplayMaxItems)

type authCipherDialer struct {
	base      C.Dialer
	authToken string
	cipherKey string
}

func newAuthCipherDialer(base C.Dialer, authToken string, cipherKey string) C.Dialer {
	return &authCipherDialer{base: base, authToken: authToken, cipherKey: cipherKey}
}

func (dialer *authCipherDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	conn, err := dialer.base.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if dialer.cipherKey != "" {
		conn = newAuthCipherAEADConn(conn, dialer.cipherKey)
	}
	if dialer.authToken != "" {
		if _, err = writeFullAuthCipherConn(conn, []byte(dialer.authToken)); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func (dialer *authCipherDialer) ListenPacket(ctx context.Context, network string, address string, remoteAddr netip.AddrPort) (net.PacketConn, error) {
	packetConn, err := dialer.base.ListenPacket(ctx, network, address, remoteAddr)
	if err != nil {
		return nil, err
	}
	return &authCipherPacketConn{PacketConn: packetConn, authToken: dialer.authToken, cipherKey: dialer.cipherKey}, nil
}

type authCipherAEADConn struct {
	net.Conn
	masterKey [32]byte
	wCipher   cipher.AEAD
	rCipher   cipher.AEAD
	wNonce    []byte
	rNonce    []byte
	buf       []byte
	offset    int
	wSaltSent bool
	rSaltRead bool
	lenBuf    [2]byte
	rLenBuf   []byte
	rBuf      []byte
}

var authCipherMasterKeyCache sync.Map

func newAuthCipherAEADConn(conn net.Conn, password string) net.Conn {
	return &authCipherAEADConn{Conn: conn, masterKey: deriveAuthCipherMasterKey(password)}
}

func deriveAuthCipherMasterKey(password string) [32]byte {
	if cached, ok := authCipherMasterKeyCache.Load(password); ok {
		return cached.([32]byte)
	}
	key := sha256.Sum256([]byte(password))
	authCipherMasterKeyCache.Store(password, key)
	return key
}

func writeFullAuthCipherConn(conn net.Conn, data []byte) (int, error) {
	written := 0
	for len(data) > 0 {
		count, err := conn.Write(data)
		if count > 0 {
			written += count
			data = data[count:]
		}
		if err != nil {
			return written, err
		}
		if count == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func newAuthCipherAEADWithSalt(masterKey [32]byte, salt []byte) (cipher.AEAD, error) {
	var keyBuf [32 + authCipherAEADSaltSize]byte
	copy(keyBuf[:32], masterKey[:])
	copy(keyBuf[32:], salt)
	key := sha256.Sum256(keyBuf[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (conn *authCipherAEADConn) initWrite() error {
	if conn.wSaltSent {
		return nil
	}

	var salt [authCipherAEADSaltSize]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return err
	}
	if _, err := writeFullAuthCipherConn(conn.Conn, salt[:]); err != nil {
		return err
	}

	aeadCipher, err := newAuthCipherAEADWithSalt(conn.masterKey, salt[:])
	if err != nil {
		return err
	}
	conn.wCipher = aeadCipher
	conn.wNonce = make([]byte, aeadCipher.NonceSize())
	conn.wSaltSent = true
	return nil
}

func (conn *authCipherAEADConn) initRead() error {
	if conn.rSaltRead {
		return nil
	}

	var salt [authCipherAEADSaltSize]byte
	if _, err := io.ReadFull(conn.Conn, salt[:]); err != nil {
		return err
	}

	aeadCipher, err := newAuthCipherAEADWithSalt(conn.masterKey, salt[:])
	if err != nil {
		return err
	}
	conn.rCipher = aeadCipher
	conn.rNonce = make([]byte, aeadCipher.NonceSize())
	conn.rLenBuf = make([]byte, 2+aeadCipher.Overhead())
	conn.rSaltRead = true
	return nil
}

func (conn *authCipherAEADConn) releaseReadBuffer() {
	if conn.rBuf != nil {
		_ = pool.Put(conn.rBuf[:cap(conn.rBuf)])
		conn.rBuf = nil
	}
	conn.buf = nil
	conn.offset = 0
}

func incrementAuthCipherNonce(nonce []byte) {
	for index := 0; index < len(nonce); index++ {
		nonce[index]++
		if nonce[index] != 0 {
			break
		}
	}
}

func authCipherAEADWriteBufferSize(payloadSize int, overhead int) int {
	if payloadSize <= 0 {
		return 0
	}
	chunkCount := payloadSize / authCipherAEADChunkSize
	if payloadSize%authCipherAEADChunkSize != 0 {
		chunkCount++
	}
	return payloadSize + chunkCount*(2+2*overhead)
}

func authCipherAEADPlaintextWritten(ciphertextWritten int, payloadSize int, overhead int) int {
	plaintextWritten := 0
	for payloadSize > 0 {
		chunkSize := payloadSize
		if chunkSize > authCipherAEADChunkSize {
			chunkSize = authCipherAEADChunkSize
		}

		frameSize := chunkSize + 2 + 2*overhead
		if ciphertextWritten < frameSize {
			break
		}

		ciphertextWritten -= frameSize
		payloadSize -= chunkSize
		plaintextWritten += chunkSize
	}
	return plaintextWritten
}

func (conn *authCipherAEADConn) Write(data []byte) (int, error) {
	if err := conn.initWrite(); err != nil {
		return 0, err
	}

	total := len(data)
	if total == 0 {
		return 0, nil
	}

	overhead := conn.wCipher.Overhead()
	writeBuf := pool.Get(authCipherAEADWriteBufferSize(total, overhead))
	defer func() { _ = pool.Put(writeBuf[:cap(writeBuf)]) }()
	encrypted := writeBuf[:0]
	for len(data) > 0 {
		chunk := data
		if len(chunk) > authCipherAEADChunkSize {
			chunk = chunk[:authCipherAEADChunkSize]
		}
		data = data[len(chunk):]

		binary.BigEndian.PutUint16(conn.lenBuf[:], uint16(len(chunk)))
		encrypted = conn.wCipher.Seal(encrypted, conn.wNonce, conn.lenBuf[:], nil)
		incrementAuthCipherNonce(conn.wNonce)

		encrypted = conn.wCipher.Seal(encrypted, conn.wNonce, chunk, nil)
		incrementAuthCipherNonce(conn.wNonce)
	}

	if ciphertextWritten, err := writeFullAuthCipherConn(conn.Conn, encrypted); err != nil {
		return authCipherAEADPlaintextWritten(ciphertextWritten, total, overhead), err
	}
	return total, nil
}

func (conn *authCipherAEADConn) Read(data []byte) (int, error) {
	if conn.offset < len(conn.buf) {
		count := copy(data, conn.buf[conn.offset:])
		conn.offset += count
		if conn.offset == len(conn.buf) {
			conn.releaseReadBuffer()
		}
		return count, nil
	}
	conn.releaseReadBuffer()

	if err := conn.initRead(); err != nil {
		return 0, err
	}

	if _, err := io.ReadFull(conn.Conn, conn.rLenBuf); err != nil {
		return 0, err
	}
	lenBuf, err := conn.rCipher.Open(conn.rLenBuf[:0], conn.rNonce, conn.rLenBuf, nil)
	if err != nil {
		return 0, errors.New("auth cipher aead read length: " + err.Error())
	}
	incrementAuthCipherNonce(conn.rNonce)

	payloadLen := binary.BigEndian.Uint16(lenBuf)
	if int(payloadLen) > authCipherAEADChunkSize {
		return 0, errors.New("auth cipher aead read: chunk size too large")
	}

	conn.rBuf = pool.Get(int(payloadLen) + conn.rCipher.Overhead())
	payloadTag := conn.rBuf[:int(payloadLen)+conn.rCipher.Overhead()]
	if _, err := io.ReadFull(conn.Conn, payloadTag); err != nil {
		conn.releaseReadBuffer()
		return 0, err
	}
	payload, err := conn.rCipher.Open(payloadTag[:0], conn.rNonce, payloadTag, nil)
	if err != nil {
		conn.releaseReadBuffer()
		return 0, errors.New("auth cipher aead read payload: " + err.Error())
	}
	incrementAuthCipherNonce(conn.rNonce)

	conn.buf = payload
	conn.offset = 0

	count := copy(data, conn.buf)
	conn.offset += count
	if conn.offset == len(conn.buf) {
		conn.releaseReadBuffer()
	}
	return count, nil
}

func (conn *authCipherAEADConn) Close() error {
	conn.releaseReadBuffer()
	return conn.Conn.Close()
}

func (conn *authCipherAEADConn) CloseWrite() error {
	if closeWriter, ok := conn.Conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return nil
}

func sealAuthCipherAEADPacket(packet []byte, password string) ([]byte, error) {
	var salt [authCipherAEADSaltSize]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return nil, err
	}
	aeadCipher, err := newAuthCipherAEADWithSalt(deriveAuthCipherMasterKey(password), salt[:])
	if err != nil {
		return nil, err
	}

	var nonce [12]byte
	sealed := make([]byte, 0, authCipherAEADSaltSize+len(packet)+aeadCipher.Overhead())
	sealed = append(sealed, salt[:]...)
	return aeadCipher.Seal(sealed, nonce[:aeadCipher.NonceSize()], packet, nil), nil
}

func openAuthCipherAEADPacketInPlace(packet []byte, password string) ([]byte, error) {
	if len(packet) < authCipherAEADSaltSize {
		return nil, errors.New("auth cipher aead packet too short")
	}
	aeadCipher, err := newAuthCipherAEADWithSalt(deriveAuthCipherMasterKey(password), packet[:authCipherAEADSaltSize])
	if err != nil {
		return nil, err
	}
	if len(packet) < authCipherAEADSaltSize+aeadCipher.Overhead() {
		return nil, errors.New("auth cipher aead packet too short")
	}

	var nonce [12]byte
	ciphertextLen := copy(packet, packet[authCipherAEADSaltSize:])
	return aeadCipher.Open(packet[:0], nonce[:aeadCipher.NonceSize()], packet[:ciphertextLen], nil)
}

type authCipherPacketConn struct {
	net.PacketConn
	authToken string
	cipherKey string
}

func (packetConn *authCipherPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	for {
		count, addr, err := packetConn.PacketConn.ReadFrom(data)
		if err != nil {
			return count, addr, err
		}

		packet, ok := openAuthCipherUDPPacketInPlace(data[:count], packetConn.authToken, packetConn.cipherKey)
		if !ok {
			continue
		}
		return len(packet), addr, nil
	}
}

func (packetConn *authCipherPacketConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	packet, err := sealAuthCipherUDPPacket(data, packetConn.authToken, packetConn.cipherKey)
	if err != nil {
		return 0, err
	}
	if _, err := packetConn.PacketConn.WriteTo(packet, addr); err != nil {
		return 0, err
	}
	return len(data), nil
}

func openAuthCipherUDPPacketInPlace(packet []byte, authToken string, cipherKey string) ([]byte, bool) {
	var err error
	if cipherKey != "" {
		packet, err = openAuthCipherAEADPacketInPlace(packet, cipherKey)
		if err != nil {
			return nil, false
		}
	}
	if authToken == "" {
		if cipherKey == "" {
			return packet, true
		}
		return openAuthCipherUDPReplayProtectedPacket(packet, 0)
	}
	if !authCipherConstantTimePrefix(packet, authToken) {
		return nil, false
	}
	return openAuthCipherUDPReplayProtectedPacket(packet, len(authToken))
}

func authCipherConstantTimePrefix(packet []byte, prefix string) bool {
	if len(packet) < len(prefix) {
		return false
	}
	var diff byte
	for index := 0; index < len(prefix); index++ {
		diff |= packet[index] ^ prefix[index]
	}
	return diff == 0
}

func sealAuthCipherUDPPacket(packet []byte, authToken string, cipherKey string) ([]byte, error) {
	if authToken == "" && cipherKey == "" {
		return packet, nil
	}

	plain := make([]byte, 0, len(authToken)+authCipherUDPHeaderSize+len(packet))
	if authToken != "" {
		plain = append(plain, authToken...)
	}
	var err error
	plain, err = appendAuthCipherUDPReplayHeader(plain, time.Now())
	if err != nil {
		return nil, err
	}
	plain = append(plain, packet...)
	if cipherKey == "" {
		return plain, nil
	}
	return sealAuthCipherAEADPacket(plain, cipherKey)
}

func appendAuthCipherUDPReplayHeader(dst []byte, now time.Time) ([]byte, error) {
	dst = append(dst, authCipherUDPSecurityMagic...)
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(now.Unix()))
	dst = append(dst, timestamp[:]...)

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return append(dst, nonce[:]...), nil
}

func openAuthCipherUDPReplayProtectedPacket(packet []byte, headerOffset int) ([]byte, bool) {
	if len(packet) < headerOffset+authCipherUDPHeaderSize {
		return nil, false
	}
	header := packet[headerOffset:]
	if !authCipherConstantTimePrefix(header, authCipherUDPSecurityMagic) {
		return nil, false
	}

	timestampStart := len(authCipherUDPSecurityMagic)
	nonceStart := timestampStart + 8
	timestamp := int64(binary.BigEndian.Uint64(header[timestampStart:nonceStart]))
	if !authCipherUDPReplay.checkAndStore(timestamp, header[nonceStart:authCipherUDPHeaderSize], time.Now()) {
		return nil, false
	}
	payloadOffset := headerOffset + authCipherUDPHeaderSize
	copy(packet, packet[payloadOffset:])
	return packet[:len(packet)-payloadOffset], true
}

type authCipherUDPReplayKey [16]byte

type authCipherUDPReplayCache struct {
	mu            sync.Mutex
	seen          map[authCipherUDPReplayKey]int64
	buckets       map[int64][]authCipherUDPReplayKey
	windowSeconds int64
	maxEntries    int
	lastPrune     int64
}

func newAuthCipherUDPReplayCache(window time.Duration, maxEntries int) *authCipherUDPReplayCache {
	return &authCipherUDPReplayCache{
		seen:          make(map[authCipherUDPReplayKey]int64),
		buckets:       make(map[int64][]authCipherUDPReplayKey),
		windowSeconds: int64(window / time.Second),
		maxEntries:    maxEntries,
	}
}

func (cache *authCipherUDPReplayCache) checkAndStore(timestamp int64, nonce []byte, now time.Time) bool {
	if len(nonce) != len(authCipherUDPReplayKey{}) {
		return false
	}
	nowSec := now.Unix()
	if timestamp < nowSec-cache.windowSeconds || timestamp > nowSec+cache.windowSeconds {
		return false
	}

	var key authCipherUDPReplayKey
	copy(key[:], nonce)
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if cache.lastPrune != nowSec {
		cache.pruneLocked(nowSec)
		cache.lastPrune = nowSec
	}
	if _, ok := cache.seen[key]; ok {
		return false
	}
	if cache.maxEntries > 0 && len(cache.seen) >= cache.maxEntries {
		cache.evictOldestLocked()
		if len(cache.seen) >= cache.maxEntries {
			return false
		}
	}

	cache.seen[key] = timestamp
	cache.buckets[timestamp] = append(cache.buckets[timestamp], key)
	return true
}

func (cache *authCipherUDPReplayCache) pruneLocked(nowSec int64) {
	expireBefore := nowSec - cache.windowSeconds
	for timestamp, keys := range cache.buckets {
		if timestamp >= expireBefore {
			continue
		}
		for _, key := range keys {
			delete(cache.seen, key)
		}
		delete(cache.buckets, timestamp)
	}
}

func (cache *authCipherUDPReplayCache) evictOldestLocked() {
	var oldest int64
	found := false
	for timestamp := range cache.buckets {
		if !found || timestamp < oldest {
			oldest = timestamp
			found = true
		}
	}
	if !found {
		return
	}
	for _, key := range cache.buckets[oldest] {
		delete(cache.seen, key)
	}
	delete(cache.buckets, oldest)
}
