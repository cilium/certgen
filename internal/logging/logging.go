// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"github.com/cilium/certgen/internal/logging/logfields"

	cfsslLog "github.com/cloudflare/cfssl/log"
	"github.com/sirupsen/logrus"
)

// DefaultLogger is the logrus logger instance used through the certgen
// packages.
var DefaultLogger = logrus.New()

func init() {
	cfsslLog.SetLogger(&sysLogger{
		l: DefaultLogger.WithField(logfields.LogSubsys, "cfssl"),
	})
}

// sysLogger wraps logrus to implement the cfsslLog.SyslogWriter
type sysLogger struct {
	l *logrus.Entry
}

// Debug implements cfsslLog.SyslogWriter
func (s *sysLogger) Debug(msg string) {
	s.l.WithField(logfields.LogSyslog, "debug").Debug(msg)
}

// Info implements cfsslLog.SyslogWriter
func (s *sysLogger) Info(msg string) {
	s.l.WithField(logfields.LogSyslog, "info").Info(msg)
}

// Warning implements cfsslLog.SyslogWriter
func (s *sysLogger) Warning(msg string) {
	s.l.WithField(logfields.LogSyslog, "warning").Warn(msg)
}

// Error implements cfsslLog.SyslogWriter
func (s *sysLogger) Err(msg string) {
	s.l.WithField(logfields.LogSyslog, "err").Error(msg)
}

// Crit implements cfsslLog.SyslogWriter
func (s *sysLogger) Crit(msg string) {
	s.l.WithField(logfields.LogSyslog, "crit").Error(msg)
}

// Emerg implements cfsslLog.SyslogWriter
func (s *sysLogger) Emerg(msg string) {
	s.l.WithField(logfields.LogSyslog, "emerg").Error(msg)
}
