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

package generate

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/cilium/certgen/internal/logging"
	"github.com/cilium/certgen/internal/logging/logfields"
	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "generate")
)

// CA contains the data and metadata of the certificate and keyfile
type Cert struct {
	CommonName       string
	ValidityDuration time.Duration
	Usage            []string
	Name             string
	Namespace        string
	Hosts            []string

	CertBytes []byte
	KeyBytes  []byte
}

// NewCert creates a new certificate blueprint
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

// WithHosts modifies to use the given hosts instead of the default (CommonName)
func (c *Cert) WithHosts(hosts []string) *Cert {
	c.Hosts = hosts
	return c
}

// Generate the certificate and keyfile and populate c.CertBytes and c.CertKey
func (c *Cert) Generate(ca *x509.Certificate, caSigner crypto.Signer) error {
	log.WithFields(logrus.Fields{
		logfields.CertCommonName:       c.CommonName,
		logfields.CertValidityDuration: c.ValidityDuration,
		logfields.CertUsage:            c.Usage,
	}).Info("Creating CSR for certificate")

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

	policy := &config.Signing{
		Default: &config.SigningProfile{
			Usage:  c.Usage,
			Expiry: c.ValidityDuration,
		},
	}
	s, err := local.NewSigner(caSigner, ca, signer.DefaultSigAlgo(caSigner), policy)
	if err != nil {
		return err
	}

	signReq := signer.SignRequest{Request: string(csrBytes)}
	certBytes, err := s.Sign(signReq)
	if err != nil {
		return err
	}

	c.CertBytes = certBytes
	c.KeyBytes = keyBytes
	return nil
}

// StoreAsSecret creates or updates the certificate and keyfile in a K8s secret
func (c *Cert) StoreAsSecret(ctx context.Context, k8sClient *kubernetes.Clientset) error {
	if c.CertBytes == nil || c.KeyBytes == nil {
		return fmt.Errorf("cannot create secret %s/%s from empty certificate",
			c.Namespace, c.Name)
	}

	log.WithFields(logrus.Fields{
		logfields.K8sSecretNamespace: c.Namespace,
		logfields.K8sSecretName:      c.Name,
	}).Info("Creating K8s Secret")

	secret := &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      c.Name,
			Namespace: c.Namespace,
		},
		Data: map[string][]byte{
			"tls.crt": c.CertBytes,
			"tls.key": c.KeyBytes,
		},
		Type: v1.SecretTypeTLS,
	}

	k8sSecrets := k8sClient.CoreV1().Secrets(c.Namespace)
	_, err := k8sSecrets.Create(ctx, secret, meta_v1.CreateOptions{})
	if k8sErrors.IsAlreadyExists(err) {
		_, err = k8sSecrets.Update(ctx, secret, meta_v1.UpdateOptions{})
	}
	return err
}

// StoreAsSecretWithCACert creates or updates the certificate, keyfile, and ca cert in a K8s secret
func (c *Cert) StoreAsSecretWithCACert(ctx context.Context, k8sClient *kubernetes.Clientset, ca *CA) error {
	if c.CertBytes == nil || c.KeyBytes == nil || ca.CACertBytes == nil {
		return fmt.Errorf("cannot create secret %s/%s from empty certificate",
			c.Namespace, c.Name)
	}

	log.WithFields(logrus.Fields{
		logfields.K8sSecretNamespace: c.Namespace,
		logfields.K8sSecretName:      c.Name,
	}).Info("Creating K8s Secret")

	secret := &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      c.Name,
			Namespace: c.Namespace,
		},
		Data: map[string][]byte{
			"tls.crt": c.CertBytes,
			"tls.key": c.KeyBytes,
			"ca.crt":  ca.CACertBytes,
		},
		Type: v1.SecretTypeTLS,
	}

	k8sSecrets := k8sClient.CoreV1().Secrets(c.Namespace)
	_, err := k8sSecrets.Create(ctx, secret, meta_v1.CreateOptions{})
	if k8sErrors.IsAlreadyExists(err) {
		_, err = k8sSecrets.Update(ctx, secret, meta_v1.UpdateOptions{})
	}
	return err
}

// CA contains the data and metadata of the certificate authority
type CA struct {
	Name      string
	Namespace string

	CACertBytes []byte
	CAKeyBytes  []byte

	CACert *x509.Certificate
	CAKey  crypto.Signer
}

// NewCA creates a new root CA blueprint
func NewCA(name, namespace string) *CA {
	return &CA{
		Name:      name,
		Namespace: namespace,
	}
}

// loadKeyPair populates c.CACert/c.CAKey from c.CACertBytes/c.CAKeyBytes
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

// Generate the root certificate and keyfile. Populates c.CACertBytes and c.CAKeyBytes
func (c *CA) Generate(commonName string, validityDuration time.Duration) error {
	log.WithFields(logrus.Fields{
		logfields.CertCommonName:       commonName,
		logfields.CertValidityDuration: validityDuration,
	}).Info("Creating CSR for certificate authority")

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

// LoadFromFile populates c.CACertBytes and c.CAKeyBytes by reading them from file.
func (c *CA) LoadFromFile(caCertFile, caKeyFile string) error {
	if caCertFile == "" || caKeyFile == "" {
		return errors.New("path for CA key and cert file must both be provided if CA is not generated")
	}

	caCertBytes, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return fmt.Errorf("failed to load CA cert file: %w", err)
	}

	caKeyBytes, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load Hubble CA key file: %w", err)
	}

	c.CACertBytes = caCertBytes
	c.CAKeyBytes = caKeyBytes
	return c.loadKeyPair()
}

// StoreAsConfigMap creates or updates the CA certificate in a K8s configmap
func (c *CA) StoreAsConfigMap(ctx context.Context, k8sClient *kubernetes.Clientset) error {
	if c.CACertBytes == nil || c.CAKeyBytes == nil {
		return fmt.Errorf("cannot create configmap %s/%s from empty certificate",
			c.Namespace, c.Name)
	}

	log.WithFields(logrus.Fields{
		logfields.K8sConfigMapNamespace: c.Namespace,
		logfields.K8sConfigMapName:      c.Name,
	}).Info("Creating K8s ConfigMap")

	configMap := &v1.ConfigMap{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      c.Name,
			Namespace: c.Namespace,
		},
		BinaryData: map[string][]byte{
			"ca.crt": c.CACertBytes,
		},
	}

	k8sConfigMaps := k8sClient.CoreV1().ConfigMaps(c.Namespace)
	_, err := k8sConfigMaps.Create(ctx, configMap, meta_v1.CreateOptions{})
	if k8sErrors.IsAlreadyExists(err) {
		_, err = k8sConfigMaps.Update(ctx, configMap, meta_v1.UpdateOptions{})
	}
	return err
}

// StoreAsSecret creates or updates the CA certificate in a K8s secret
func (c *CA) StoreAsSecret(ctx context.Context, k8sClient *kubernetes.Clientset) error {
	if c.CACertBytes == nil || c.CAKeyBytes == nil {
		return fmt.Errorf("cannot create secret %s/%s from empty certificate",
			c.Namespace, c.Name)
	}

	log.WithFields(logrus.Fields{
		logfields.K8sSecretNamespace: c.Namespace,
		logfields.K8sSecretName:      c.Name,
	}).Info("Creating K8s Secret")

	secret := &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      c.Name,
			Namespace: c.Namespace,
		},
		Data: map[string][]byte{
			"ca.crt": c.CACertBytes,
			"ca.key": c.CAKeyBytes,
		},
	}

	k8sSecrets := k8sClient.CoreV1().Secrets(c.Namespace)
	_, err := k8sSecrets.Create(ctx, secret, meta_v1.CreateOptions{})
	if k8sErrors.IsAlreadyExists(err) {
		_, err = k8sSecrets.Update(ctx, secret, meta_v1.UpdateOptions{})
	}
	return err
}

// LoadFromSecret populates c.CACertBytes and c.CAKeyBytes by reading them from a secret
func (c *CA) LoadFromSecret(ctx context.Context, k8sClient *kubernetes.Clientset) error {
	k8sSecrets := k8sClient.CoreV1().Secrets(c.Namespace)
	secret, err := k8sSecrets.Get(ctx, c.Name, meta_v1.GetOptions{})
	if err != nil {
		return err
	}

	if len(secret.Data["ca.crt"]) == 0 {
		return fmt.Errorf("Secret %s/%s has no CA cert", c.Namespace, c.Name)
	}

	if len(secret.Data["ca.key"]) == 0 {
		return fmt.Errorf("Secret %s/%s has no CA key", c.Namespace, c.Name)
	}

	c.CACertBytes = secret.Data["ca.crt"]
	c.CAKeyBytes = secret.Data["ca.key"]

	return c.loadKeyPair()
}
