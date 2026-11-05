package log

import (
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestLogLevelDuringConcurrentLogging(t *testing.T) {
	previous := Level()
	t.Cleanup(func() { SetLevel(previous) })

	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for range 1000 {
			SetLevel(INFO)
			SetLevel(WARNING)
			SetLevel(SILENT)
		}
	}()
	for range 1000 {
		if current := Level(); current < INFO || current > SILENT {
			t.Errorf("unexpected log level: %v", current)
		}
		Debugln("connection cleanup")
	}
	writer.Wait()
}

func TestLogPayloadLimitPreservesUTF8AndFiltersOriginal(t *testing.T) {
	payload := strings.Repeat("界🙂", MaxPayloadBytes)
	bounded := (Event{LogLevel: WARNING, Payload: payload}).Bounded()
	if len(bounded.Payload) > MaxPayloadBytes || !utf8.ValidString(bounded.Payload) || !strings.HasSuffix(bounded.Payload, "... [truncated]") || bounded.LogLevel != WARNING {
		t.Fatal("oversized log lost its UTF-8 boundary, size limit or severity")
	}
	previous := EventFilter
	defer func() { EventFilter = previous }()
	sawOriginal := false
	EventFilter = func(event Event) bool {
		sawOriginal = event.Payload == payload
		return false
	}
	emit(Event{Payload: payload})
	if !sawOriginal {
		t.Fatal("output filtering ran after truncation")
	}
}
