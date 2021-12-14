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

package option

import (
	"time"

	"github.com/spf13/viper"
)

// Config is the main configuration as obtained from command-line arguments,
// environment variables and config files.
var Config = &CertGenConfig{}

const (
	Debug = "debug"

	CACertFile = "ca-cert-file"
	CAKeyFile  = "ca-key-file"

	CAGenerate         = "ca-generate"
	CAReuseSecret      = "ca-reuse-secret"
	CACommonName       = "ca-common-name"
	CAValidityDuration = "ca-validity-duration"
	CASecretName       = "ca-secret-name"
	CASecretNamespace  = "ca-secret-namespace"

	HubbleServerCertGenerate         = "hubble-server-cert-generate"
	HubbleServerCertCommonName       = "hubble-server-cert-common-name"
	HubbleServerCertValidityDuration = "hubble-server-cert-validity-duration"
	HubbleServerCertSecretName       = "hubble-server-cert-secret-name"
	HubbleServerCertSecretNamespace  = "hubble-server-cert-secret-namespace"

	HubbleRelayServerCertGenerate         = "hubble-relay-server-cert-generate"
	HubbleRelayServerCertCommonName       = "hubble-relay-server-cert-common-name"
	HubbleRelayServerCertValidityDuration = "hubble-relay-server-cert-validity-duration"
	HubbleRelayServerCertSecretName       = "hubble-relay-server-cert-secret-name"
	HubbleRelayServerCertSecretNamespace  = "hubble-relay-server-cert-secret-namespace"

	HubbleRelayClientCertGenerate         = "hubble-relay-client-cert-generate"
	HubbleRelayClientCertCommonName       = "hubble-relay-client-cert-common-name"
	HubbleRelayClientCertValidityDuration = "hubble-relay-client-cert-validity-duration"
	HubbleRelayClientCertSecretName       = "hubble-relay-client-cert-secret-name"
	HubbleRelayClientCertSecretNamespace  = "hubble-relay-client-cert-secret-namespace"

	CiliumNamespace = "cilium-namespace"

	ClustermeshApiserverServerCertGenerate         = "clustermesh-apiserver-server-cert-generate"
	ClustermeshApiserverServerCertCommonName       = "clustermesh-apiserver-server-cert-common-name"
	ClustermeshApiserverServerCertValidityDuration = "clustermesh-apiserver-server-cert-validity-duration"
	ClustermeshApiserverServerCertSecretName       = "clustermesh-apiserver-server-cert-secret-name"
	ClustermeshApiserverServerCertSANs             = "clustermesh-apiserver-server-cert-sans"

	ClustermeshApiserverAdminCertGenerate         = "clustermesh-apiserver-admin-cert-generate"
	ClustermeshApiserverAdminCertCommonName       = "clustermesh-apiserver-admin-cert-common-name"
	ClustermeshApiserverAdminCertValidityDuration = "clustermesh-apiserver-admin-cert-validity-duration"
	ClustermeshApiserverAdminCertSecretName       = "clustermesh-apiserver-admin-cert-secret-name"

	ClustermeshApiserverClientCertGenerate         = "clustermesh-apiserver-client-cert-generate"
	ClustermeshApiserverClientCertCommonName       = "clustermesh-apiserver-client-cert-common-name"
	ClustermeshApiserverClientCertValidityDuration = "clustermesh-apiserver-client-cert-validity-duration"
	ClustermeshApiserverClientCertSecretName       = "clustermesh-apiserver-client-cert-secret-name"

	ClustermeshApiserverRemoteCertGenerate         = "clustermesh-apiserver-remote-cert-generate"
	ClustermeshApiserverRemoteCertCommonName       = "clustermesh-apiserver-remote-cert-common-name"
	ClustermeshApiserverRemoteCertValidityDuration = "clustermesh-apiserver-remote-cert-validity-duration"
	ClustermeshApiserverRemoteCertSecretName       = "clustermesh-apiserver-remote-cert-secret-name"

	K8sKubeConfigPath = "k8s-kubeconfig-path"
	K8sRequestTimeout = "k8s-request-timeout"
)

// CertGenConfig contains the main configuration options
type CertGenConfig struct {
	// Debug enables debug messages
	Debug bool

	// K8sKubeConfigPath is the path to the kubeconfig
	// If empty, the in-cluster configuration is used
	K8sKubeConfigPath string

	// K8sRequestTimeout specifies the timeout for K8s API requests
	K8sRequestTimeout time.Duration

	// CACertFile is the path to the Cilium CA cert PEM (if CAGenerate is false)
	CACertFile string
	// CAKeyFile is the path to the Cilium CA key PEM (if CAGenerate is false)
	CAKeyFile string

	// CAGenerate can be set to true to generate a new Cilium CA secret.
	// If CAReuseSecret is true, then a new CA secret only is created if existing one is not found.
	CAGenerate bool
	// CAReuseSecret can be set to true to store and load the Cilium CA from the secret if
	// it exists. Delete the old Secret to force regeneration.
	CAReuseSecret bool
	// CACommonName is the CN of the Cilium CA
	CACommonName string
	// CAValidityDuration of certificate
	CAValidityDuration time.Duration
	// CASecretName where the Cilium CA cert and key will be stored
	CASecretName string
	// CASecretNamespace where the Cilium CA cert and key will be stored
	CASecretNamespace string

	// HubbleRelayClientCertGenerate can be set to true to generate and store a Hubble Relay client cert
	HubbleRelayClientCertGenerate bool
	// HubbleRelayClientCertCommonName is the CN of the Hubble Relay client cert
	HubbleRelayClientCertCommonName string
	// HubbleRelayClientCertValidityDuration of certificate
	HubbleRelayClientCertValidityDuration time.Duration
	// HubbleRelayClientCertSecretName where the Hubble Relay client cert and key will be stored
	HubbleRelayClientCertSecretName string
	// HubbleRelayClientCertSecretNamespace where the Hubble Relay client cert and key will be stored
	HubbleRelayClientCertSecretNamespace string

	// HubbleRelayServerCertGenerate can be set to true to generate and store a Hubble Relay server cert
	HubbleRelayServerCertGenerate bool
	// HubbleRelayServerCertCommonName is the CN of the Hubble Relay server cert
	HubbleRelayServerCertCommonName string
	// HubbleRelayServerCertValidityDuration of certificate
	HubbleRelayServerCertValidityDuration time.Duration
	// HubbleRelayServerCertSecretName where the Hubble Relay server cert and key will be stored
	HubbleRelayServerCertSecretName string
	// HubbleRelayServerCertSecretNamespace where the Hubble Relay server cert and key will be stored
	HubbleRelayServerCertSecretNamespace string

	// HubbleServerCertGenerate can be set to true to generate and store a Hubble server cert
	HubbleServerCertGenerate bool
	// HubbleServerCertCommonName is the CN of the Hubble server cert
	HubbleServerCertCommonName string
	// HubbleServerCertValidityDuration of certificate
	HubbleServerCertValidityDuration time.Duration
	// HubbleServerCertSecretName where the Hubble server cert and key will be stored
	HubbleServerCertSecretName string
	// HubbleServerCertSecretNamespace where the Hubble server cert and key will be stored
	HubbleServerCertSecretNamespace string

	// CiliumNamespace where the secrets and configmaps will be stored
	CiliumNamespace string

	// ClustermeshApiserverServerCertGenerate can be set to true to generate and store a new ClustermeshApiserver server secret.
	// If true then any existing secret is overwritten with a new one.
	ClustermeshApiserverServerCertGenerate bool
	// ClustermeshApiserverServerCertCommonName is the CN of the ClustermeshApiserver server cert
	ClustermeshApiserverServerCertCommonName string
	// ClustermeshApiserverServerCertValidityDuration of certificate
	ClustermeshApiserverServerCertValidityDuration time.Duration
	// ClustermeshApiserverServerCertSecretName where the ClustermeshApiserver server cert and key will be stored
	ClustermeshApiserverServerCertSecretName string
	// ClustermeshApiserverServerCertSANs is the list of SANs to add to the clustermesh-apiserver server certificate.
	ClustermeshApiserverServerCertSANs []string

	// ClustermeshApiserverAdminCertGenerate can be set to true to generate and store a new ClustermeshApiserver admin secret.
	// If true then any existing secret is overwritten with a new one.
	ClustermeshApiserverAdminCertGenerate bool
	// ClustermeshApiserverAdminCertCommonName is the CN of the ClustermeshApiserver admin cert
	ClustermeshApiserverAdminCertCommonName string
	// ClustermeshApiserverAdminCertValidityDuration of certificate
	ClustermeshApiserverAdminCertValidityDuration time.Duration
	// ClustermeshApiserverAdminCertSecretName where the ClustermeshApiserver admin cert and key will be stored
	ClustermeshApiserverAdminCertSecretName string

	// ClustermeshApiserverClientCertGenerate can be set to true to generate and store a new ClustermeshApiserver client secret.
	// If true then any existing secret is overwritten with a new one.
	ClustermeshApiserverClientCertGenerate bool
	// ClustermeshApiserverClientCertCommonName is the CN of the ClustermeshApiserver client cert
	ClustermeshApiserverClientCertCommonName string
	// ClustermeshApiserverClientCertValidityDuration of certificate
	ClustermeshApiserverClientCertValidityDuration time.Duration
	// ClustermeshApiserverClientCertSecretName where the ClustermeshApiserver client cert and key will be stored
	ClustermeshApiserverClientCertSecretName string

	// ClustermeshApiserverRemoteCertGenerate can be set to true to generate and store a new ClustermeshApiserver remote secret.
	// If true then any existing secret is overwritten with a new one.
	ClustermeshApiserverRemoteCertGenerate bool
	// ClustermeshApiserverRemoteCertCommonName is the CN of the ClustermeshApiserver remote cert
	ClustermeshApiserverRemoteCertCommonName string
	// ClustermeshApiserverRemoteCertValidityDuration of certificate
	ClustermeshApiserverRemoteCertValidityDuration time.Duration
	// ClustermeshApiserverRemoteCertSecretName where the ClustermeshApiserver remote cert and key will be stored
	ClustermeshApiserverRemoteCertSecretName string
}

// getStringWithFallback returns the value associated with the key as a string
// if it is non-empty. If the value is empty, this function returns the value
// associated with fallbackKey
func getStringWithFallback(vp *viper.Viper, key, fallbackKey string) string {
	if value := vp.GetString(key); value != "" {
		return value
	}
	return vp.GetString(fallbackKey)
}

// PopulateFrom populates the config struct with the values provided by vp
func (c *CertGenConfig) PopulateFrom(vp *viper.Viper) {
	c.Debug = vp.GetBool(Debug)
	c.K8sKubeConfigPath = vp.GetString(K8sKubeConfigPath)
	c.K8sRequestTimeout = vp.GetDuration(K8sRequestTimeout)

	c.CACertFile = vp.GetString(CACertFile)
	c.CAKeyFile = vp.GetString(CAKeyFile)

	c.CAGenerate = vp.GetBool(CAGenerate)
	c.CAReuseSecret = vp.GetBool(CAReuseSecret)
	c.CACommonName = vp.GetString(CACommonName)
	c.CAValidityDuration = vp.GetDuration(CAValidityDuration)
	c.CASecretName = vp.GetString(CASecretName)
	c.CASecretNamespace = getStringWithFallback(vp, CASecretNamespace, CiliumNamespace)

	c.HubbleRelayClientCertGenerate = vp.GetBool(HubbleRelayClientCertGenerate)
	c.HubbleRelayClientCertCommonName = vp.GetString(HubbleRelayClientCertCommonName)
	c.HubbleRelayClientCertValidityDuration = vp.GetDuration(HubbleRelayClientCertValidityDuration)
	c.HubbleRelayClientCertSecretName = vp.GetString(HubbleRelayClientCertSecretName)
	c.HubbleRelayClientCertSecretNamespace = getStringWithFallback(vp, HubbleRelayClientCertSecretNamespace, CiliumNamespace)

	c.HubbleRelayServerCertGenerate = vp.GetBool(HubbleRelayServerCertGenerate)
	c.HubbleRelayServerCertCommonName = vp.GetString(HubbleRelayServerCertCommonName)
	c.HubbleRelayServerCertValidityDuration = vp.GetDuration(HubbleRelayServerCertValidityDuration)
	c.HubbleRelayServerCertSecretName = vp.GetString(HubbleRelayServerCertSecretName)
	c.HubbleRelayServerCertSecretNamespace = getStringWithFallback(vp, HubbleRelayServerCertSecretNamespace, CiliumNamespace)

	c.HubbleServerCertGenerate = vp.GetBool(HubbleServerCertGenerate)
	c.HubbleServerCertCommonName = vp.GetString(HubbleServerCertCommonName)
	c.HubbleServerCertValidityDuration = vp.GetDuration(HubbleServerCertValidityDuration)
	c.HubbleServerCertSecretName = vp.GetString(HubbleServerCertSecretName)
	c.HubbleServerCertSecretNamespace = getStringWithFallback(vp, HubbleServerCertSecretNamespace, CiliumNamespace)

	c.CiliumNamespace = vp.GetString(CiliumNamespace)

	c.ClustermeshApiserverServerCertGenerate = vp.GetBool(ClustermeshApiserverServerCertGenerate)
	c.ClustermeshApiserverServerCertCommonName = vp.GetString(ClustermeshApiserverServerCertCommonName)
	c.ClustermeshApiserverServerCertValidityDuration = vp.GetDuration(ClustermeshApiserverServerCertValidityDuration)
	c.ClustermeshApiserverServerCertSecretName = vp.GetString(ClustermeshApiserverServerCertSecretName)
	c.ClustermeshApiserverServerCertSANs = vp.GetStringSlice(ClustermeshApiserverServerCertSANs)

	c.ClustermeshApiserverAdminCertGenerate = vp.GetBool(ClustermeshApiserverAdminCertGenerate)
	c.ClustermeshApiserverAdminCertCommonName = vp.GetString(ClustermeshApiserverAdminCertCommonName)
	c.ClustermeshApiserverAdminCertValidityDuration = vp.GetDuration(ClustermeshApiserverAdminCertValidityDuration)
	c.ClustermeshApiserverAdminCertSecretName = vp.GetString(ClustermeshApiserverAdminCertSecretName)

	c.ClustermeshApiserverClientCertGenerate = vp.GetBool(ClustermeshApiserverClientCertGenerate)
	c.ClustermeshApiserverClientCertCommonName = vp.GetString(ClustermeshApiserverClientCertCommonName)
	c.ClustermeshApiserverClientCertValidityDuration = vp.GetDuration(ClustermeshApiserverClientCertValidityDuration)
	c.ClustermeshApiserverClientCertSecretName = vp.GetString(ClustermeshApiserverClientCertSecretName)

	c.ClustermeshApiserverRemoteCertGenerate = vp.GetBool(ClustermeshApiserverRemoteCertGenerate)
	c.ClustermeshApiserverRemoteCertCommonName = vp.GetString(ClustermeshApiserverRemoteCertCommonName)
	c.ClustermeshApiserverRemoteCertValidityDuration = vp.GetDuration(ClustermeshApiserverRemoteCertValidityDuration)
	c.ClustermeshApiserverRemoteCertSecretName = vp.GetString(ClustermeshApiserverRemoteCertSecretName)
}
