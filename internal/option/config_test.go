// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCertGenConfigValidate checks that incomplete CA pairs are rejected.
func TestCertGenConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *CertGenConfig
		wantErr string
	}{
		{
			name: "only CA cert file",
			cfg: &CertGenConfig{
				CACertFile: "ca.crt",
			},
			wantErr: "must specify both --ca-cert-file and --ca-key-file together",
		},
		{
			name: "only CA key file",
			cfg: &CertGenConfig{
				CAKeyFile: "ca.key",
			},
			wantErr: "must specify both --ca-cert-file and --ca-key-file together",
		},
		{
			name: "only configmap name",
			cfg: &CertGenConfig{
				CAConfigMapName: "ca",
			},
			wantErr: "must specify both --ca-configmap-name and --ca-configmap-namespace together",
		},
		{
			name: "only configmap namespace",
			cfg: &CertGenConfig{
				CAConfigMapNamespace: "kube-system",
			},
			wantErr: "must specify both --ca-configmap-name and --ca-configmap-namespace together",
		},
		{
			name: "complete pairs",
			cfg: &CertGenConfig{
				CACertFile:           "ca.crt",
				CAKeyFile:            "ca.key",
				CAConfigMapName:      "ca",
				CAConfigMapNamespace: "kube-system",
			},
		},
		{
			name: "empty config",
			cfg:  &CertGenConfig{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.EqualError(t, err, tt.wantErr)
		})
	}
}
