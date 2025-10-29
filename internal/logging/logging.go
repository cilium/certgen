// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"log/slog"
	"os"

	"github.com/cilium/certgen/internal/logging/logfields"

	cfsslLog "github.com/cloudflare/cfssl/log"
)

// Level is a runtime-configurable log level used by Logger.
var Level = new(slog.LevelVar)

// Logger is the log/slog logger instance used through the certgen packages.
var Logger = slog.New(
	slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: Level,
	}),
)

func init() {
	cfsslLog.SetLogger(&sysLogger{
		l: Logger.With(logfields.LogSubsys, "cfssl"), //nolint:sloglint
	})
}

// sysLogger wraps slog to implement the cfsslLog.SyslogWriter.
type sysLogger struct {
	l *slog.Logger
}

// Debug implements cfsslLog.SyslogWriter.
func (s *sysLogger) Debug(msg string) {
	s.l.Debug(msg, logfields.LogSyslog, "debug") //nolint:sloglint
}

// Info implements cfsslLog.SyslogWriter.
func (s *sysLogger) Info(msg string) {
	s.l.Info(msg, logfields.LogSyslog, "info") //nolint:sloglint
}

// Warning implements cfsslLog.SyslogWriter.
func (s *sysLogger) Warning(msg string) {
	s.l.Warn(msg, logfields.LogSyslog, "warning") //nolint:sloglint
}

// Err implements cfsslLog.SyslogWriter.
func (s *sysLogger) Err(msg string) {
	s.l.Error(msg, logfields.LogSyslog, "err") //nolint:sloglint
}

// Crit implements cfsslLog.SyslogWriter.
func (s *sysLogger) Crit(msg string) {
	s.l.Error(msg, logfields.LogSyslog, "crit") //nolint:sloglint
}

// Emerg implements cfsslLog.SyslogWriter.
func (s *sysLogger) Emerg(msg string) {
	s.l.Error(msg, logfields.LogSyslog, "emerg") //nolint:sloglint
}
