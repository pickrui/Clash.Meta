package log

import (
	"fmt"
	"os"
	"sync/atomic"
	"unicode/utf8"

	"github.com/metacubex/mihomo/common/observable"

	log "github.com/sirupsen/logrus"
)

var (
	logCh  = make(chan Event)
	source = observable.NewObservable[Event](logCh)
	level  atomic.Int32
)

var EventFilter func(Event) bool

func init() {
	level.Store(int32(INFO))
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:             true,
		TimestampFormat:           "2006-01-02T15:04:05.000000000Z07:00",
		EnvironmentOverrideColors: true,
	})
}

type Event struct {
	LogLevel LogLevel
	Payload  string
}

const MaxPayloadBytes = 16 * 1024

func (e Event) Bounded() Event {
	if len(e.Payload) > MaxPayloadBytes {
		const suffix = "... [truncated]"
		end := MaxPayloadBytes - len(suffix)
		for end > 0 && !utf8.RuneStart(e.Payload[end]) {
			end--
		}
		e.Payload = e.Payload[:end] + suffix
	}
	return e
}

func (e *Event) Type() string {
	return e.LogLevel.String()
}

func Infoln(format string, v ...any) {
	emit(newLog(INFO, format, v...))
}

func Warnln(format string, v ...any) {
	emit(newLog(WARNING, format, v...))
}

func Errorln(format string, v ...any) {
	emit(newLog(ERROR, format, v...))
}

func Debugln(format string, v ...any) {
	emit(newLog(DEBUG, format, v...))
}

func emit(event Event) {
	if EventFilter != nil && !EventFilter(event) {
		return
	}
	event = event.Bounded()
	logCh <- event
	print(event)
}

func Fatalln(format string, v ...any) {
	if EventFilter != nil && !EventFilter(newLog(ERROR, format, v...)) {
		os.Exit(1)
	}
	log.Fatalf(format, v...)
}

func Subscribe() observable.Subscription[Event] {
	sub, _ := source.Subscribe()
	return sub
}

func UnSubscribe(sub observable.Subscription[Event]) {
	source.UnSubscribe(sub)
}

func Level() LogLevel {
	return LogLevel(level.Load())
}

func SetLevel(newLevel LogLevel) {
	level.Store(int32(newLevel))
}

func print(data Event) {
	if data.LogLevel < Level() {
		return
	}

	switch data.LogLevel {
	case INFO:
		log.Infoln(data.Payload)
	case WARNING:
		log.Warnln(data.Payload)
	case ERROR:
		log.Errorln(data.Payload)
	case DEBUG:
		log.Debugln(data.Payload)
	}
}

func newLog(logLevel LogLevel, format string, v ...any) Event {
	return Event{
		LogLevel: logLevel,
		Payload:  fmt.Sprintf(format, v...),
	}
}
