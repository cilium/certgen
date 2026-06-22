// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package generate

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

// TestCertStoreAsSecretUpdatesExistingSecret verifies reruns preserve the
// current resourceVersion when updating an existing leaf secret.
func TestCertStoreAsSecretUpdatesExistingSecret(t *testing.T) {
	t.Parallel()

	clientset, server := newSecretTestClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			writeStatusError(t, w, http.StatusConflict, apierrors.NewAlreadyExists(
				schema.GroupResource{Resource: "secrets"},
				"leaf",
			))
		case http.MethodGet:
			writeJSON(t, w, &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:            "leaf",
					Namespace:       testNamespace,
					ResourceVersion: "123",
				},
			})
		case http.MethodPut:
			var secret v1.Secret
			decodeJSON(t, r, &secret)
			if secret.ResourceVersion != "123" {
				t.Fatalf("expected resourceVersion to be preserved, got %q", secret.ResourceVersion)
			}
			writeJSON(t, w, &secret)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	})
	defer server.Close()

	logger := slog.New(slog.DiscardHandler)
	ca := mustGenerateCA(t, logger)
	cert := NewCert("test", time.Hour, []string{serverAuth}, "leaf", testNamespace)
	if err := cert.Generate(logger, ca); err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	if err := cert.StoreAsSecret(context.Background(), logger, clientset); err != nil {
		t.Fatalf("failed to store secret: %v", err)
	}
}

// TestCAStoreAsSecretForceUpdatesExistingSecret verifies force overwrites keep
// the current resourceVersion when updating an existing CA secret.
func TestCAStoreAsSecretForceUpdatesExistingSecret(t *testing.T) {
	t.Parallel()

	clientset, server := newSecretTestClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			writeStatusError(t, w, http.StatusConflict, apierrors.NewAlreadyExists(
				schema.GroupResource{Resource: "secrets"},
				"ca",
			))
		case http.MethodGet:
			writeJSON(t, w, &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:            "ca",
					Namespace:       testNamespace,
					ResourceVersion: "456",
				},
			})
		case http.MethodPut:
			var secret v1.Secret
			decodeJSON(t, r, &secret)
			if secret.ResourceVersion != "456" {
				t.Fatalf("expected resourceVersion to be preserved, got %q", secret.ResourceVersion)
			}
			writeJSON(t, w, &secret)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	})
	defer server.Close()

	logger := slog.New(slog.DiscardHandler)
	ca := mustGenerateCA(t, logger)
	ca.SecretName = "ca"
	ca.SecretNamespace = testNamespace

	if err := ca.StoreAsSecret(context.Background(), logger, clientset, true); err != nil {
		t.Fatalf("failed to store CA secret: %v", err)
	}
}

func mustGenerateCA(t *testing.T, logger *slog.Logger) *CA {
	t.Helper()

	ca, err := NewCA(CAConfig{
		SecretName:      "ca",
		SecretNamespace: testNamespace,
	})
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	if err := ca.Generate(logger, "test-ca", time.Hour); err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	return ca
}

func newSecretTestClientset(t *testing.T, handler func(http.ResponseWriter, *http.Request)) (*kubernetes.Clientset, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/default/secrets/leaf" && r.URL.Path != "/api/v1/namespaces/default/secrets/ca" && r.URL.Path != "/api/v1/namespaces/default/secrets" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		handler(w, r)
	}))

	clientset, err := kubernetes.NewForConfig(&rest.Config{
		Host: server.URL,
		ContentConfig: rest.ContentConfig{
			ContentType:          "application/json",
			AcceptContentTypes:   "application/json",
			NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
		},
	})
	if err != nil {
		server.Close()
		t.Fatalf("failed to create clientset: %v", err)
	}

	return clientset, server
}

func writeStatusError(t *testing.T, w http.ResponseWriter, statusCode int, err error) {
	t.Helper()

	statusErr := &apierrors.StatusError{}
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected status error, got %T", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if encodeErr := json.NewEncoder(w).Encode(statusErr.ErrStatus); encodeErr != nil {
		t.Fatalf("failed to encode status error: %v", encodeErr)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, obj any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(obj); err != nil {
		t.Fatalf("failed to encode response: %v", err)
	}
}

func decodeJSON(t *testing.T, r *http.Request, obj any) {
	t.Helper()

	if err := json.NewDecoder(r.Body).Decode(obj); err != nil {
		t.Fatalf("failed to decode request: %v", err)
	}
}
