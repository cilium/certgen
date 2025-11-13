// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package generate

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/certgen/internal/logging/logfields"
)

// Cert contains the data and metadata of the certificate and keyfile.
type Cert struct {
	CommonName       string
	ValidityDuration time.Duration
	Usage            []string
	Name             string
	Namespace        string
	Hosts            []string

	CA        *CA
	CertBytes []byte
	KeyBytes  []byte
}

// NewCert creates a new certificate blueprint.
func NewCert(
	commonName string,
	validityDuration time.Duration,
	usage []string,
	name string,
	namespace string,
) *Cert {
	return &Cert{
		CommonName:       commonName,
		Hosts:            []string{commonName},
		ValidityDuration: validityDuration,
		Usage:            usage,
		Name:             name,
		Namespace:        namespace,
	}
}

// WithHosts modifies to use the given hosts instead of the default
// (CommonName).
func (c *Cert) WithHosts(hosts []string) *Cert {
	c.Hosts = hosts
	return c
}

// Generate the certificate and keyfile and populate c.CertBytes and c.CertKey.
func (c *Cert) Generate(log *slog.Logger, ca *CA) error {
	log.Info("Creating CSR for certificate",
		logfields.CertCommonName, c.CommonName,
		logfields.CertValidityDuration, c.ValidityDuration.String(),
		logfields.CertUsage, c.Usage,
	)

	certRequest := &csr.CertificateRequest{
		CN:         c.CommonName,
		Hosts:      c.Hosts,
		KeyRequest: csr.NewKeyRequest(),
	}

	g := &csr.Generator{Validator: genkey.Validator}
	csrBytes, keyBytes, err := g.ProcessRequest(certRequest)
	if err != nil {
		return err
	}

	for _, usage := range c.Usage {
		_, ok1 := config.KeyUsage[usage]
		_, ok2 := config.ExtKeyUsage[usage]
		if !ok1 && !ok2 {
			return fmt.Errorf("invalid key usage %q", usage)
		}
	}

	policy := &config.Signing{
		Default: &config.SigningProfile{
			Usage:  c.Usage,
			Expiry: c.ValidityDuration,
		},
	}
	caCert, caSigner := ca.CACert, ca.CAKey
	s, err := local.NewSigner(caSigner, caCert, signer.DefaultSigAlgo(caSigner), policy)
	if err != nil {
		return err
	}

	signReq := signer.SignRequest{Request: string(csrBytes)}
	certBytes, err := s.Sign(signReq)
	if err != nil {
		return err
	}

	c.CA = ca
	c.CertBytes = certBytes
	c.KeyBytes = keyBytes
	return nil
}

// StoreAsSecret creates or updates the certificate and keyfile in a K8s secret.
func (c *Cert) StoreAsSecret(ctx context.Context, log *slog.Logger, k8sClient *kubernetes.Clientset) error {
	if c.CertBytes == nil || c.KeyBytes == nil {
		return fmt.Errorf("cannot create secret %s/%s from empty certificate",
			c.Namespace, c.Name)
	}

	scopedLog := log.With(
		slog.String(logfields.K8sSecretNamespace, c.Namespace),
		slog.String(logfields.K8sSecretName, c.Name),
	)
	scopedLog.Info("Creating K8s Secret")

	secret := &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      c.Name,
			Namespace: c.Namespace,
		},
		Data: map[string][]byte{
			"ca.crt":  c.CA.CACertBytes,
			"tls.crt": c.CertBytes,
			"tls.key": c.KeyBytes,
		},
		Type: v1.SecretTypeTLS,
	}

	k8sSecrets := k8sClient.CoreV1().Secrets(c.Namespace)
	_, err := k8sSecrets.Create(ctx, secret, meta_v1.CreateOptions{})
	if k8sErrors.IsAlreadyExists(err) {
		scopedLog.Info("Secret already exists, updating it instead")
		_, err = k8sSecrets.Update(ctx, secret, meta_v1.UpdateOptions{})
	}
	return err
}

// CA contains the data and metadata of the certificate authority.
type CA struct {
	SecretName      string
	SecretNamespace string

	CACertBytes []byte
	CAKeyBytes  []byte

	CACert *x509.Certificate
	CAKey  crypto.Signer
}

// NewCA creates a new root CA blueprint.
func NewCA(secretName, secretNamespace string) *CA {
	return &CA{
		SecretName:      secretName,
		SecretNamespace: secretNamespace,
	}
}

// loadKeyPair populates c.CACert/c.CAKey from c.CACertBytes/c.CAKeyBytes.
func (c *CA) loadKeyPair() error {
	caCert, err := helpers.ParseCertificatePEM(c.CACertBytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA cert PEM: %w", err)
	}

	caKey, err := helpers.ParsePrivateKeyPEM(c.CAKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA key PEM: %w", err)
	}

	c.CACert = caCert
	c.CAKey = caKey
	return nil
}

// IsEmpty returns true if this CA is empty.
func (c *CA) IsEmpty() bool {
	return c.CAKey == nil && c.CACert == nil
}

// Reset resets ca key and ca cert values, this is useful for reload or
// regeneration.
func (c *CA) Reset() {
	c.CAKey = nil
	c.CACert = nil
}

// Generate the root certificate and keyfile. Populates c.CACertBytes and
// c.CAKeyBytes.
func (c *CA) Generate(log *slog.Logger, commonName string, validityDuration time.Duration) error {
	log.Info("Creating CSR for certificate authority",
		logfields.CertCommonName, commonName,
		logfields.CertValidityDuration, validityDuration.String(),
	)

	caCSR := &csr.CertificateRequest{
		CN: commonName,
		CA: &csr.CAConfig{
			Expiry: validityDuration.String(),
		},
		KeyRequest: csr.NewKeyRequest(),
	}
	caCertBytes, _, caKeyBytes, err := initca.New(caCSR)
	if err != nil {
		return err
	}

	c.CACertBytes = caCertBytes
	c.CAKeyBytes = caKeyBytes
	return c.loadKeyPair()
}

// LoadFromFile populates c.CACertBytes and c.CAKeyBytes by reading them from
// file.
func (c *CA) LoadFromFile(caCertFile, caKeyFile string) error {
	if caCertFile == "" || caKeyFile == "" {
		return errors.New("path for CA key and cert file must both be provided if CA is not generated")
	}

	caCertBytes, err := os.ReadFile(caCertFile)
	if err != nil {
		return fmt.Errorf("failed to load CA cert file: %w", err)
	}

	caKeyBytes, err := os.ReadFile(caKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load Hubble CA key file: %w", err)
	}

	c.CACertBytes = caCertBytes
	c.CAKeyBytes = caKeyBytes
	return c.loadKeyPair()
}

// StoreAsSecret creates or updates the CA certificate in a K8s secret.
//   - If force is true, the existing secret with same name in same namespace
//     (if available) will be overwritten.
//   - If force is false and there is existing secret with same name in same
//     namespace, just throws IsAlreadyExists error to caller.
func (c *CA) StoreAsSecret(ctx context.Context, log *slog.Logger, k8sClient *kubernetes.Clientset, force bool) error {
	if c.CACertBytes == nil || c.CAKeyBytes == nil {
		return fmt.Errorf("cannot create secret %s/%s from empty certificate",
			c.SecretNamespace, c.SecretName)
	}

	scopedLog := log.With(
		slog.String(logfields.K8sSecretNamespace, c.SecretNamespace),
		slog.String(logfields.K8sSecretName, c.SecretName),
	)
	scopedLog.Info("Creating K8s Secret")

	secret := &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      c.SecretName,
			Namespace: c.SecretNamespace,
		},
		Data: map[string][]byte{
			"ca.crt": c.CACertBytes,
			"ca.key": c.CAKeyBytes,
		},
	}

	k8sSecrets := k8sClient.CoreV1().Secrets(c.SecretNamespace)
	_, err := k8sSecrets.Create(ctx, secret, meta_v1.CreateOptions{})
	if k8sErrors.IsAlreadyExists(err) {
		if force {
			scopedLog.Info("Secret already exists, overwrite existing one instead")
			_, err = k8sSecrets.Update(ctx, secret, meta_v1.UpdateOptions{})
		} else {
			scopedLog.Warn("Secret already exists")
			return err
		}
	}
	return err
}

// LoadFromSecret populates c.CACertBytes and c.CAKeyBytes by reading them from
// a secret.
func (c *CA) LoadFromSecret(ctx context.Context, k8sClient *kubernetes.Clientset) error {
	k8sSecrets := k8sClient.CoreV1().Secrets(c.SecretNamespace)
	secret, err := k8sSecrets.Get(ctx, c.SecretName, meta_v1.GetOptions{})
	if err != nil {
		return err
	}

	if len(secret.Data["ca.crt"]) == 0 {
		return fmt.Errorf("secret %s/%s has no CA cert", c.SecretNamespace, c.SecretName)
	}

	if len(secret.Data["ca.key"]) == 0 {
		return fmt.Errorf("secret %s/%s has no CA key", c.SecretNamespace, c.SecretName)
	}

	c.CACertBytes = secret.Data["ca.crt"]
	c.CAKeyBytes = secret.Data["ca.key"]

	if err := c.loadKeyPair(); err != nil {
		return err
	}

	return nil
}
