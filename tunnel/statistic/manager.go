package statistic

import (
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/memory"
)

var DefaultManager *Manager

var TrackerInfoFilter func(*TrackerInfo) bool

func init() {
	DefaultManager = &Manager{
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
		pid:           int32(os.Getpid()),
	}
}

type Manager struct {
	connections        xsync.Map[string, Tracker]
	uploadTotal        atomic.Int64
	downloadTotal      atomic.Int64
	proxyUploadTotal   atomic.Int64
	proxyDownloadTotal atomic.Int64
	pid                int32
	memory             uint64
	rateMu             sync.Mutex
	rateAt             time.Time
	rateReadAt         time.Time
	rateTotals         [4]int64
	rates              [4]int64
}

func (m *Manager) Join(c Tracker) {
	if DefaultRequestNotify != nil && (TrackerInfoFilter == nil || TrackerInfoFilter(c.Info())) {
		DefaultRequestNotify(c)
	}
	m.connections.Store(c.ID(), c)
}

func (m *Manager) Leave(c Tracker) {
	m.connections.Delete(c.ID())
}

func (m *Manager) Get(id string) (c Tracker) {
	if value, ok := m.connections.Load(id); ok {
		c = value
	}
	return
}

func (m *Manager) Range(f func(c Tracker) bool) {
	m.connections.Range(func(key string, value Tracker) bool {
		return f(value)
	})
}

func (m *Manager) PushUploaded(direct bool, size int64) {
	if !direct {
		m.proxyUploadTotal.Add(size)
	}
	m.uploadTotal.Add(size)
}

func (m *Manager) PushDownloaded(direct bool, size int64) {
	if !direct {
		m.proxyDownloadTotal.Add(size)
	}
	m.downloadTotal.Add(size)
}

func (m *Manager) Now() (up int64, down int64) {
	return m.NowTraffic(false)
}

func (m *Manager) Total() (up, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) Memory() uint64 {
	m.updateMemory()
	return m.memory
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []*TrackerInfo
	m.Range(func(c Tracker) bool {
		info := c.Info()
		if TrackerInfoFilter == nil || TrackerInfoFilter(info) {
			connections = append(connections, info)
		}
		return true
	})
	return &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
		Memory:        m.memory,
	}
}

func (m *Manager) updateMemory() {
	stat, err := memory.GetMemoryInfo(m.pid)
	if err != nil {
		return
	}
	m.memory = stat.RSS
}

func (m *Manager) ResetStatistic() {
	m.rateMu.Lock()
	defer m.rateMu.Unlock()
	m.uploadTotal.Store(0)
	m.downloadTotal.Store(0)
	m.proxyUploadTotal.Store(0)
	m.proxyDownloadTotal.Store(0)
	m.rateAt = time.Time{}
	m.rateReadAt = time.Time{}
	m.rateTotals = [4]int64{}
	m.rates = [4]int64{}
}

// Readers within half a second share a sample, so each jittery 1 Hz poll gets a
// fresh rate; a dormant reader restarts its baseline so traffic accumulated
// with a hidden window cannot become a rate spike.
func (m *Manager) sampleRates(now time.Time) [4]int64 {
	m.rateMu.Lock()
	defer m.rateMu.Unlock()
	if now.Before(m.rateReadAt) {
		return m.rates
	}
	totals := [4]int64{m.uploadTotal.Load(), m.downloadTotal.Load(), m.proxyUploadTotal.Load(), m.proxyDownloadTotal.Load()}
	if m.rateAt.IsZero() || now.Sub(m.rateReadAt) >= 5*time.Second {
		m.rates = [4]int64{}
		m.rateTotals = totals
		m.rateAt = now
	} else if elapsed := now.Sub(m.rateAt); elapsed >= 500*time.Millisecond {
		for i, total := range totals {
			m.rates[i] = int64(float64(max(0, total-m.rateTotals[i])) / elapsed.Seconds())
		}
		m.rateTotals = totals
		m.rateAt = now
	}
	m.rateReadAt = now
	return m.rates
}

type Snapshot struct {
	DownloadTotal int64          `json:"downloadTotal"`
	UploadTotal   int64          `json:"uploadTotal"`
	Connections   []*TrackerInfo `json:"connections"`
	Memory        uint64         `json:"memory"`
}
