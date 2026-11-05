package statistic

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestDemandRatesShareSamplesAndDiscardDormantTraffic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := &Manager{}
		m.PushUploaded(false, 500)
		if up, down := m.Now(); up != 0 || down != 0 {
			t.Fatal("first reader included traffic before its sampling window")
		}
		m.PushUploaded(true, 100)
		m.PushUploaded(false, 200)
		m.PushDownloaded(false, 600)
		time.Sleep(time.Second)
		if up, down := m.Now(); up != 300 || down != 600 {
			t.Fatalf("all rates = %d/%d", up, down)
		}
		if up, down := m.NowTraffic(true); up != 200 || down != 600 {
			t.Fatalf("second consumer lost shared proxy rates: %d/%d", up, down)
		}
		m.PushUploaded(false, 400)
		time.Sleep(2 * time.Second)
		if up, _ := m.Now(); up != 200 {
			t.Fatalf("delayed reader did not normalize elapsed time: %d", up)
		}
		m.PushUploaded(false, 1_000_000)
		time.Sleep(time.Hour)
		if up, down := m.Now(); up != 0 || down != 0 {
			t.Fatal("dormant reader produced a traffic spike")
		}
		if up, down := m.Total(); up != 1_001_200 || down != 600 {
			t.Fatalf("dormant sampling lost cumulative traffic: %d/%d", up, down)
		}
		m.PushUploaded(false, 100)
		time.Sleep(time.Second)
		if up, _ := m.NowTraffic(true); up != 100 {
			t.Fatalf("sampling did not resume: %d", up)
		}
		m.ResetStatistic()
		if up, down := m.Now(); up != 0 || down != 0 {
			t.Fatal("reset retained a rate sample")
		}
		time.Sleep(time.Second)
		if up, down := m.NowTraffic(true); up != 0 || down != 0 {
			t.Fatal("reset subtracted an obsolete baseline")
		}
	})
}

func TestJitteredOneSecondPollsEachReadAFreshRate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := &Manager{}
		m.Now()
		for _, gap := range []time.Duration{995 * time.Millisecond, 1005 * time.Millisecond, 990 * time.Millisecond, 995 * time.Millisecond} {
			m.PushDownloaded(false, 5*gap.Milliseconds())
			time.Sleep(gap)
			if _, down := m.Now(); down != 5000 {
				t.Fatalf("poll after %v read %d B/s, want 5000", gap, down)
			}
		}
		m.PushDownloaded(false, 5000)
		time.Sleep(400 * time.Millisecond)
		if _, down := m.NowTraffic(true); down != 5000 {
			t.Fatalf("reader within half a second did not share the last sample: %d", down)
		}
	})
}

func TestConcurrentRateReadersPreserveTrafficTotals(t *testing.T) {
	m := &Manager{}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 1000 {
				m.PushUploaded(false, 1)
				m.PushDownloaded(true, 2)
				m.Now()
				m.NowTraffic(true)
			}
		})
	}
	workers.Wait()
	if up, down := m.Total(); up != 8000 || down != 16000 {
		t.Fatalf("traffic total = %d/%d", up, down)
	}
	if up, down := m.TotalTraffic(true); up != 8000 || down != 0 {
		t.Fatalf("proxy total = %d/%d", up, down)
	}
}
