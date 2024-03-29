package rfc

/*
 * ZLint Copyright 2023 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type generalizedNoSeconds struct {
}

/********************************************************************
4.1.2.5.2.  GeneralizedTime
The generalized time type, GeneralizedTime, is a standard ASN.1 type
for variable precision representation of time.  Optionally, the
GeneralizedTime field can include a representation of the time
differential between local and Greenwich Mean Time.

For the purposes of this profile, GeneralizedTime values MUST be
expressed in Greenwich Mean Time (Zulu) and MUST include seconds
(i.e., times are YYYYMMDDHHMMSSZ), even where the number of seconds
is zero.  GeneralizedTime values MUST NOT include fractional seconds.
********************************************************************/

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_generalized_time_does_not_include_seconds",
			Description:   "Generalized time values MUST include seconds",
			Citation:      "RFC 5280: 4.1.2.5.2",
			Source:        lint.RFC5280,
			EffectiveDate: util.RFC2459Date,
		},
		Lint: NewGeneralizedNoSeconds,
	})
}

func NewGeneralizedNoSeconds() lint.LintInterface {
	return &generalizedNoSeconds{}
}

func (l *generalizedNoSeconds) CheckApplies(c *x509.Certificate) bool {
	firstDate, secondDate := util.GetTimes(c)
	beforeTag, afterTag := util.FindTimeType(firstDate, secondDate)
	date1Gen := beforeTag == 24
	date2Gen := afterTag == 24
	return date1Gen || date2Gen
}

func (l *generalizedNoSeconds) Execute(c *x509.Certificate) *lint.LintResult {
	r := lint.Pass
	date1, date2 := util.GetTimes(c)
	beforeTag, afterTag := util.FindTimeType(date1, date2)
	date1Gen := beforeTag == 24
	date2Gen := afterTag == 24
	if date1Gen {
		// UTC Tests on notBefore
		checkSeconds(&r, date1)
		if r == lint.Error {
			return &lint.LintResult{Status: r}
		}
	}
	if date2Gen {
		checkSeconds(&r, date2)
	}
	return &lint.LintResult{Status: r}
}

//nolint:nestif
func checkSeconds(r *lint.LintStatus, t asn1.RawValue) {
	if t.Bytes[len(t.Bytes)-1] == 'Z' {
		if len(t.Bytes) < 15 {
			*r = lint.Error
		}
	} else if t.Bytes[len(t.Bytes)-5] == '-' || t.Bytes[len(t.Bytes)-1] == '+' {
		if len(t.Bytes) < 19 {
			*r = lint.Error
		}
	} else {
		if len(t.Bytes) < 14 {
			*r = lint.Error
		}
	}
}
