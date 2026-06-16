// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package generate

import (
	"log/slog"
	"testing"
	"time"
)

// TestCertGenerateRequiresCA verifies generation fails without a usable CA.
func TestCertGenerateRequiresCA(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	cert := NewCert("test", time.Hour, []string{"server auth"}, "test", "default")

	tests := []struct {
		name string
		ca   *CA
	}{
		{
			name: "nil CA",
			ca:   nil,
		},
		{
			name: "empty CA",
			ca:   &CA{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := cert.Generate(logger, tt.ca)
			if err == nil {
				t.Fatal("expected error")
			}

			const want = "cannot generate certificate without a loaded or generated CA"
			if err.Error() != want {
				t.Fatalf("unexpected error: got %q want %q", err.Error(), want)
			}
		})
	}
}

// TestCertGenerateWithCA verifies generation succeeds with a CA.
func TestCertGenerateWithCA(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)

	ca, err := NewCA(CAConfig{
		SecretName:      "ca",
		SecretNamespace: "default",
	})
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	if err := ca.Generate(logger, "test-ca", time.Hour); err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	cert := NewCert("test", time.Hour, []string{"server auth"}, "test", "default")
	if err := cert.Generate(logger, ca); err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	if len(cert.CertBytes) == 0 {
		t.Fatal("expected generated certificate bytes")
	}

	if len(cert.KeyBytes) == 0 {
		t.Fatal("expected generated key bytes")
	}
}
