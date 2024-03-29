package cabf_br

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
	"crypto/rsa"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type rootCaModSize struct{}

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_old_root_ca_rsa_mod_less_than_2048_bits",
			Description:   "In a validity period beginning on or before 31 Dec 2010, root CA certificates using RSA public key algorithm MUST use a 2048 bit modulus",
			Citation:      "BRs: 6.1.5",
			Source:        lint.CABFBaselineRequirements,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewRootCaModSize,
	})
}

func NewRootCaModSize() lint.LintInterface {
	return &rootCaModSize{}
}

func (l *rootCaModSize) CheckApplies(c *x509.Certificate) bool {
	issueDate := c.NotBefore
	_, ok := c.PublicKey.(*rsa.PublicKey)
	return ok && c.PublicKeyAlgorithm == x509.RSA && util.IsRootCA(c) && issueDate.Before(util.NoRSA1024RootDate)
}

func (l *rootCaModSize) Execute(c *x509.Certificate) *lint.LintResult {
	key := c.PublicKey.(*rsa.PublicKey)
	if key.N.BitLen() < 2048 {
		return &lint.LintResult{Status: lint.Error}
	} else {
		return &lint.LintResult{Status: lint.Pass}
	}
}
