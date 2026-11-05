package statistic

import "time"

type RequestNotify func(c Tracker)

var DefaultRequestNotify RequestNotify

var IsDirect = func(name string) bool { return name == "DIRECT" }

func (m *Manager) TotalTraffic(onlyProxy bool) (up, down int64) {
	if onlyProxy {
		return m.proxyUploadTotal.Load(), m.proxyDownloadTotal.Load()
	}
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) NowTraffic(onlyProxy bool) (up, down int64) {
	rates := m.sampleRates(time.Now())
	if onlyProxy {
		return rates[2], rates[3]
	}
	return rates[0], rates[1]
}
