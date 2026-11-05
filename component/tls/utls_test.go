package tls

import (
	"sync"
	"testing"
)

func TestGlobalFingerprintConcurrentAccess(t *testing.T) {
	previous := GetGlobalFingerprint()
	t.Cleanup(func() { SetGlobalFingerprint(previous) })

	var waitGroup sync.WaitGroup
	for index := 0; index < 100; index++ {
		waitGroup.Add(2)
		go func(value string) {
			defer waitGroup.Done()
			SetGlobalFingerprint(value)
		}("chrome")
		go func() {
			defer waitGroup.Done()
			_, _ = GetFingerprint("")
		}()
	}
	waitGroup.Wait()
}
