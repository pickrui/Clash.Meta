package log

import (
	"context"
	"fmt"

	L "github.com/metacubex/sing/common/logger"
)

type singLogger struct{}

func logArgs(fn func(format string, v ...any), args ...any) {
	fn("%s", fmt.Sprint(args...))
}

func (l singLogger) TraceContext(ctx context.Context, args ...any) {
	logArgs(Debugln, args...)
}

func (l singLogger) DebugContext(ctx context.Context, args ...any) {
	logArgs(Debugln, args...)
}

func (l singLogger) InfoContext(ctx context.Context, args ...any) {
	logArgs(Infoln, args...)
}

func (l singLogger) WarnContext(ctx context.Context, args ...any) {
	logArgs(Warnln, args...)
}

func (l singLogger) ErrorContext(ctx context.Context, args ...any) {
	logArgs(Errorln, args...)
}

func (l singLogger) FatalContext(ctx context.Context, args ...any) {
	logArgs(Fatalln, args...)
}

func (l singLogger) PanicContext(ctx context.Context, args ...any) {
	logArgs(Fatalln, args...)
}

func (l singLogger) Trace(args ...any) {
	logArgs(Debugln, args...)
}

func (l singLogger) Debug(args ...any) {
	logArgs(Debugln, args...)
}

func (l singLogger) Info(args ...any) {
	logArgs(Infoln, args...)
}

func (l singLogger) Warn(args ...any) {
	logArgs(Warnln, args...)
}

func (l singLogger) Error(args ...any) {
	logArgs(Errorln, args...)
}

func (l singLogger) Fatal(args ...any) {
	logArgs(Fatalln, args...)
}

func (l singLogger) Panic(args ...any) {
	logArgs(Fatalln, args...)
}

type singInfoToDebugLogger struct {
	singLogger
}

func (l singInfoToDebugLogger) InfoContext(ctx context.Context, args ...any) {
	logArgs(Debugln, args...)
}

func (l singInfoToDebugLogger) Info(args ...any) {
	logArgs(Debugln, args...)
}

var SingLogger L.ContextLogger = singLogger{}
var SingInfoToDebugLogger L.ContextLogger = singInfoToDebugLogger{}
