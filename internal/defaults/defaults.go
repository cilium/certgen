// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

import "time"

const (
	// Debug enables debug messages.
	Debug = false

	// CiliumNamespace is the Kubernetes namespace in which Cilium is
	// installed.
	CiliumNamespace = "kube-system"

	// K8sRequestTimeout specifies the timeout for K8s API requests.
	K8sRequestTimeout = 60 * time.Second

	// CAGenerate can be set to true to generate a new Cilium CA secret.
	// If CAReuseSecret is true, then a new CA secret only is created if
	// existing one is not found.
	CAGenerate = false
	// CAReuseSecret can be set to true to store and load the Cilium CA from
	// the secret if it exists. Setting to false will delete the old Secret and
	// force regeneration.
	CAReuseSecret = false
	// CACommonName is the Cilium CA x509 certificate CN value.
	CACommonName = "Cilium CA"
	// CAValidityDuration represent how much time the Cilium CA certificate
	// generated by certgen is valid.
	CAValidityDuration = 3 * 365 * 24 * time.Hour
	// CASecretName is the Kubernetes Secret in which the Cilium CA certificate
	// is read from and/or written to.
	CASecretName = "cilium-ca"

	// HubbleServerCertGenerate can be set to true to generate and store a
	// Hubble server TLS certificate.
	HubbleServerCertGenerate = false
	// HubbleServerCertCommonName is the Hubble server x509 certificate CN
	// value (also used as DNS SAN).
	HubbleServerCertCommonName = "*.default.hubble-grpc.cilium.io"
	// HubbleServerCertValidityDuration represent how much time the Hubble
	// server certificate generated by certgen is valid.
	HubbleServerCertValidityDuration = 3 * 365 * 24 * time.Hour
	// HubbleServerCertSecretName is the Kubernetes Secret in which the Hubble
	// server certificate is written to.
	HubbleServerCertSecretName = "hubble-server-certs" //#nosec

	// HubbleRelayServerCertGenerate can be set to true to generate and store a
	// Hubble Relay server TLS certificate.
	HubbleRelayServerCertGenerate = false
	// HubbleRelayServerCertCommonName is the Hubble Relay server x509
	// certificate CN value (also used as DNS SAN).
	HubbleRelayServerCertCommonName = "*.hubble-relay.cilium.io"
	// HubbleRelayServerCertValidityDuration represent how much time the Hubble
	// Relay server certificate generated by certgen is valid.
	HubbleRelayServerCertValidityDuration = 3 * 365 * 24 * time.Hour
	// HubbleRelayServerCertSecretName is the Kubernetes Secret in which the
	// Hubble Relay server certificate is written to.
	HubbleRelayServerCertSecretName = "hubble-relay-server-certs" //#nosec

	// HubbleRelayClientCertGenerate can be set to true to generate and store a
	// Hubble Relay client TLS certificate (used for the mTLS handshake with
	// the Hubble servers).
	HubbleRelayClientCertGenerate = false
	// HubbleRelayClientCertCommonName is the Hubble Relay client x509
	// certificate CN value.
	HubbleRelayClientCertCommonName = "*.hubble-relay.cilium.io"
	// HubbleRelayClientCertValidityDuration represent how much time the Hubble
	// Relay client certificate generated by certgen is valid.
	HubbleRelayClientCertValidityDuration = 3 * 365 * 24 * time.Hour
	// HubbleRelayClientCertSecretName is the Kubernetes Secret in which the
	// Hubble Relay client certificate is written to.
	HubbleRelayClientCertSecretName = "hubble-relay-client-certs" //#nosec

	// ClustermeshApiserverServerCertGenerate can be set to true to generate
	// and store a new Clustermesh API server TLS certificate.
	ClustermeshApiserverServerCertGenerate = false
	// ClustermeshApiserverServerCertCommonName is the Clustermesh API server
	// x509 certificate CN value (also used as DNS SAN).
	ClustermeshApiserverServerCertCommonName = "clustermesh-apiserver.cilium.io"
	// ClustermeshApiserverServerCertValidityDuration represent how much time
	// Clustermesh API server certificate generated by certgen is valid.
	ClustermeshApiserverServerCertValidityDuration = 3 * 365 * 24 * time.Hour
	// ClustermeshApiserverServerCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API server certificate is written to.
	ClustermeshApiserverServerCertSecretName = "clustermesh-apiserver-server-cert"

	// ClustermeshApiserverAdminCertGenerate can be set to true to generate and
	// store a new Clustermesh API admin TLS certificate.
	ClustermeshApiserverAdminCertGenerate = false
	// ClustermeshApiserverAdminCertCommonName is the Clustermesh API admin
	// x509 certificate CN value.
	ClustermeshApiserverAdminCertCommonName = "root"
	// ClustermeshApiserverAdminCertValidityDuration represent how much time
	// Clustermesh API admin certificate generated by certgen is valid.
	ClustermeshApiserverAdminCertValidityDuration = 3 * 365 * 24 * time.Hour
	// ClustermeshApiserverAdminCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API admin certificate is written to.
	ClustermeshApiserverAdminCertSecretName = "clustermesh-apiserver-admin-cert"

	// ClustermeshApiserverClientCertGenerate can be set to true to generate and
	// store a new Clustermesh API client TLS certificate.
	ClustermeshApiserverClientCertGenerate = false
	// ClustermeshApiserverClientCertCommonName is the Clustermesh API client
	// x509 certificate CN value.
	ClustermeshApiserverClientCertCommonName = "externalworkload"
	// ClustermeshApiserverClientCertValidityDuration represent how much time
	// Clustermesh API client certificate generated by certgen is valid.
	ClustermeshApiserverClientCertValidityDuration = 3 * 365 * 24 * time.Hour
	// ClustermeshApiserverClientCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API client certificate is written to.
	ClustermeshApiserverClientCertSecretName = "clustermesh-apiserver-client-cert"

	// ClustermeshApiserverRemoteCertGenerate can be set to true to generate and
	// store a new Clustermesh API remote TLS certificate.
	ClustermeshApiserverRemoteCertGenerate = false
	// ClustermeshApiserverRemoteCertCommonName is the Clustermesh API remote
	// x509 certificate CN value.
	ClustermeshApiserverRemoteCertCommonName = "remote"
	// ClustermeshApiserverRemoteCertValidityDuration represent how much time
	// Clustermesh API remote certificate generated by certgen is valid.
	ClustermeshApiserverRemoteCertValidityDuration = 3 * 365 * 24 * time.Hour
	// ClustermeshApiserverRemoteCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API remote certificate is written to.
	ClustermeshApiserverRemoteCertSecretName = "clustermesh-apiserver-remote-cert"
)

var (
	// HubbleServerCertUsage are the key usages for the Hubble server x509
	// certificate.
	HubbleServerCertUsage = []string{"signing", "key encipherment", "server auth"}
	// HubbleRelayServerCertUsage are the key usages for the Hubble Relay
	// server x509 certificate.
	HubbleRelayServerCertUsage = []string{"signing", "key encipherment", "server auth"}
	// HubbleRelayClientCertUsage are the key usages for the Hubble Relay
	// client x509 certificate.
	HubbleRelayClientCertUsage = []string{"signing", "key encipherment", "server auth", "client auth"}
	// ClustermeshApiserverCertUsage are the key usages for the Clustermesh API
	// server x509 certificate.
	ClustermeshApiserverCertUsage = []string{"signing", "key encipherment", "server auth", "client auth"}
	// ClustermeshApiserverServerCertSANs is the list of SANs to add to the
	// Clustermesh API server certificate.
	ClustermeshApiserverServerCertSANs = []string{"*.mesh.cilium.io"}
)
