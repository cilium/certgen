// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
