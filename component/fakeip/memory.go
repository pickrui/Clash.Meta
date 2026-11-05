package fakeip

import (
	"net/netip"

	"github.com/bahlo/generic-list-go"
)

type memoryEntry struct {
	host string
	ip   netip.Addr
}

// Pool.mux protects both indexes and their shared recency list.
type memoryStore struct {
	byHost  map[string]*list.Element[memoryEntry]
	byIP    map[netip.Addr]*list.Element[memoryEntry]
	entries list.List[memoryEntry]
	maxSize int
}

func (m *memoryStore) GetByHost(host string) (netip.Addr, bool) {
	if entry := m.byHost[host]; entry != nil {
		m.entries.MoveToBack(entry)
		return entry.Value.ip, true
	}
	return netip.Addr{}, false
}

func (m *memoryStore) GetByIP(ip netip.Addr) (string, bool) {
	if entry := m.byIP[ip]; entry != nil {
		m.entries.MoveToBack(entry)
		return entry.Value.host, true
	}
	return "", false
}

func (m *memoryStore) PutMapping(host string, ip netip.Addr) {
	entry := m.byHost[host]
	if previous := m.byIP[ip]; previous != nil && previous != entry {
		if entry == nil {
			entry = previous
		} else {
			m.remove(previous)
		}
	}
	if entry == nil && m.maxSize > 0 && m.entries.Len() >= m.maxSize {
		entry = m.entries.Front()
	}
	value := memoryEntry{host: host, ip: ip}
	if entry == nil {
		entry = m.entries.PushBack(value)
	} else {
		delete(m.byHost, entry.Value.host)
		delete(m.byIP, entry.Value.ip)
		entry.Value = value
		m.entries.MoveToBack(entry)
	}
	m.byHost[host], m.byIP[ip] = entry, entry
}

func (m *memoryStore) remove(entry *list.Element[memoryEntry]) {
	delete(m.byHost, entry.Value.host)
	delete(m.byIP, entry.Value.ip)
	m.entries.Remove(entry)
}

func (m *memoryStore) Exist(ip netip.Addr) bool {
	return m.byIP[ip] != nil
}

func (m *memoryStore) CloneTo(store store) {
	if ms, ok := store.(*memoryStore); ok && ms != m {
		_ = ms.FlushFakeIP()
		for entry := m.entries.Front(); entry != nil; entry = entry.Next() {
			ms.PutMapping(entry.Value.host, entry.Value.ip)
		}
	}
}

func (m *memoryStore) FlushFakeIP() error {
	m.byHost = make(map[string]*list.Element[memoryEntry])
	m.byIP = make(map[netip.Addr]*list.Element[memoryEntry])
	m.entries.Init()
	return nil
}

func newMemoryStore(size int) *memoryStore {
	m := &memoryStore{maxSize: size}
	_ = m.FlushFakeIP()
	return m
}
