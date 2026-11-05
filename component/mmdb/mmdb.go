package mmdb

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/oschwald/maxminddb-golang"
)

type databaseType = uint8

const (
	typeMaxmind databaseType = iota
	typeSing
	typeMetaV0
)

var (
	ipReader  atomic.Pointer[IPReader]
	asnReader atomic.Pointer[ASNReader]
	ipMu      sync.Mutex
	asnMu     sync.Mutex
)

func LoadFromBytes(buffer []byte) {
	ipMu.Lock()
	defer ipMu.Unlock()
	if ipReader.Load() != nil {
		return
	}
	database, err := maxminddb.FromBytes(buffer)
	if err != nil {
		log.Fatalln("Can't load mmdb: %s", err.Error())
	}
	ipReader.Store(newIPReader(database))
}

func newIPReader(database *maxminddb.Reader) *IPReader {
	reader := &IPReader{Reader: database}
	switch database.Metadata.DatabaseType {
	case "sing-geoip":
		reader.databaseType = typeSing
	case "Meta-geoip0":
		reader.databaseType = typeMetaV0
	default:
		reader.databaseType = typeMaxmind
	}
	return reader
}

func Verify(path string) bool {
	instance, err := maxminddb.Open(path)
	if err == nil {
		instance.Close()
	}
	return err == nil
}

func openDatabase(path string) (*maxminddb.Reader, error) {
	if runtime.GOOS != "windows" {
		return maxminddb.Open(path)
	}
	// Windows can reject replacement while a memory-mapped view is alive. Keep
	// the immutable database bytes instead so old readers do not pin the file.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return maxminddb.FromBytes(data)
}

func IPInstance() IPReader {
	if reader := ipReader.Load(); reader != nil {
		return *reader
	}
	ipMu.Lock()
	defer ipMu.Unlock()
	reader := ipReader.Load()
	if reader == nil {
		mmdbPath := C.Path.MMDB()
		log.Infoln("Load MMDB file: %s", mmdbPath)
		mmdb, err := openDatabase(mmdbPath)
		if err != nil {
			log.Fatalln("Can't load MMDB: %s", err.Error())
		}
		reader = newIPReader(mmdb)
		ipReader.Store(reader)
	}

	return *reader
}

func ASNInstance() ASNReader {
	if reader := asnReader.Load(); reader != nil {
		return *reader
	}
	asnMu.Lock()
	defer asnMu.Unlock()
	reader := asnReader.Load()
	if reader == nil {
		ASNPath := C.Path.ASN()
		log.Infoln("Load ASN file: %s", ASNPath)
		asn, err := openDatabase(ASNPath)
		if err != nil {
			log.Fatalln("Can't load ASN: %s", err.Error())
		}
		reader = &ASNReader{Reader: asn}
		asnReader.Store(reader)
	}

	return *reader
}

// ReloadIP invalidates the cached reader after the database file is atomically
// replaced. Existing lookups retain the old mapping until their final reference
// is released; maxminddb's finalizer then closes it.
func ReloadIP() {
	ipMu.Lock()
	defer ipMu.Unlock()
	ipReader.Store(nil)
}

// ReloadASN has the same reader lifetime guarantees as ReloadIP.
func ReloadASN() {
	asnMu.Lock()
	defer asnMu.Unlock()
	asnReader.Store(nil)
}
