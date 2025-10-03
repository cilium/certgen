// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"log/slog"
	"os"

	"github.com/cilium/certgen/internal/logging/logfields"

	cfsslLog "github.com/cloudflare/cfssl/log"
)

// DefaultLoggerLvl is a runtime-configurable log level used by DefaultLogger.
var DefaultLoggerLvl = new(slog.LevelVar)

func init() {
	// Start at INFO. Can be changed at runtime via DefaultLoggerLvl.Set(...).
	DefaultLoggerLvl.Set(slog.LevelInfo)
}

// DefaultLogger is the log/slog logger instance used through the certgen
// packages.
var DefaultLogger = slog.New(
	slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: DefaultLoggerLvl,
		// Hide empty message field
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.MessageKey && a.Value.String() == "" {
				return slog.Attr{}
			}
			return a
		},
	}),
)

func init() {
	cfsslLog.SetLogger(&sysLogger{
		l: DefaultLogger.With(logfields.LogSubsys, "cfssl"),
	})
}

// Static message literal to satisfy sloglint
const emptyMsg = ""

// sysLogger wraps slog to implement the cfsslLog.SyslogWriter
type sysLogger struct {
	l *slog.Logger
}

// Debug implements cfsslLog.SyslogWriter
func (s *sysLogger) Debug(msg string) {
	s.l.Debug(emptyMsg, logfields.LogSyslog, "debug", "detail", msg)
}

// Info implements cfsslLog.SyslogWriter
func (s *sysLogger) Info(msg string) {
	s.l.Info(emptyMsg, logfields.LogSyslog, "info", "detail", msg)
}

// Warning implements cfsslLog.SyslogWriter
func (s *sysLogger) Warning(msg string) {
	s.l.Warn(emptyMsg, logfields.LogSyslog, "warning", "detail", msg)
}

// Error implements cfsslLog.SyslogWriter
func (s *sysLogger) Err(msg string) {
	s.l.Error(emptyMsg, logfields.LogSyslog, "err", "detail", msg)
}

// Crit implements cfsslLog.SyslogWriter
func (s *sysLogger) Crit(msg string) {
	s.l.Error(emptyMsg, logfields.LogSyslog, "crit", "detail", msg)
}

// Emerg implements cfsslLog.SyslogWriter
func (s *sysLogger) Emerg(msg string) {
	s.l.Error(emptyMsg, logfields.LogSyslog, "emerg", "detail", msg)
}
