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

	HubbleCACertFile = "hubble-ca-cert-file"
	HubbleCAKeyFile  = "hubble-ca-key-file"

	HubbleCAGenerate           = "hubble-ca-generate"
	HubbleCACommonName         = "hubble-ca-common-name"
	HubbleCAValidityDuration   = "hubble-ca-validity-duration"
	HubbleCAConfigMapName      = "hubble-ca-config-map-name"
	HubbleCAConfigMapNamespace = "hubble-ca-config-map-namespace"

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

	ClustermeshApiserverCACertFile = "clustermesh-apiserver-ca-cert-file"
	ClustermeshApiserverCAKeyFile  = "clustermesh-apiserver-ca-key-file"

	ClustermeshApiserverCertsGenerate = "clustermesh-apiserver-certs-generate"

	ClustermeshApiserverCACertCommonName       = "clustermesh-apiserver-ca-cert-common-name"
	ClustermeshApiserverCACertValidityDuration = "clustermesh-apiserver-ca-cert-validity-duration"
	ClustermeshApiserverCACertSecretName       = "clustermesh-apiserver-ca-cert-secret-name"

	ClustermeshApiserverServerCertCommonName       = "clustermesh-apiserver-server-cert-common-name"
	ClustermeshApiserverServerCertValidityDuration = "clustermesh-apiserver-server-cert-validity-duration"
	ClustermeshApiserverServerCertSecretName       = "clustermesh-apiserver-server-cert-secret-name"

	ClustermeshApiserverAdminCertCommonName       = "clustermesh-apiserver-admin-cert-common-name"
	ClustermeshApiserverAdminCertValidityDuration = "clustermesh-apiserver-admin-cert-validity-duration"
	ClustermeshApiserverAdminCertSecretName       = "clustermesh-apiserver-admin-cert-secret-name"

	ClustermeshApiserverClientCertCommonName       = "clustermesh-apiserver-client-cert-common-name"
	ClustermeshApiserverClientCertValidityDuration = "clustermesh-apiserver-client-cert-validity-duration"
	ClustermeshApiserverClientCertSecretName       = "clustermesh-apiserver-client-cert-secret-name"

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

	// HubbleCACertFile is the path to the Hubble CA cert PEM (if HubbleCAGenerate is false)
	HubbleCACertFile string
	// HubbleCAKeyFile is the path to the Hubble CA key PEM (if HubbleCAGenerate is false)
	HubbleCAKeyFile string

	// HubbleCAGenerate can be set to true to generate and store a new Hubble CA
	HubbleCAGenerate bool
	// HubbleCACommonName is the CN of the Hubble CA
	HubbleCACommonName string
	// HubbleCAValidityDuration of certificate
	HubbleCAValidityDuration time.Duration
	// HubbleCAConfigMapName where the Hubble CA cert will be stored
	HubbleCAConfigMapName string
	// HubbleCAConfigMapNamespace where the Hubble CA cert will be stored
	HubbleCAConfigMapNamespace string

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

	// ClustermeshApiserverCACertFile is the path to the ClustermeshApiserver CA cert PEM (if ClustermeshApiserverCertsGenerate is false)
	ClustermeshApiserverCACertFile string
	// ClustermeshApiserverCAKeyFile is the path to the ClustermeshApiserver CA key PEM (if ClustermeshApiserverCertsGenerate is false)
	ClustermeshApiserverCAKeyFile string

	// ClustermeshApiserverCertsGenerate can be set to true to generate and store a new ClustermeshApiserver secrets and configmap
	// New CA ConfigMap is created if created if existing one is not found. Delete the old ConfigMap to force regeneration.
	// New CA is created if CA cert and key are not given.
	// Server and client certs are created on each invocation.
	ClustermeshApiserverCertsGenerate bool

	// ClustermeshApiserverCACertCommonName is the CN of the ClustermeshApiserver CA
	ClustermeshApiserverCACertCommonName string
	// ClustermeshApiserverCACertValidityDuration of certificate
	ClustermeshApiserverCACertValidityDuration time.Duration
	// ClustermeshApiserverCACertSecretName where the ClustermeshApiserver CA cert will be stored
	ClustermeshApiserverCACertSecretName string

	// ClustermeshApiserverServerCertCommonName is the CN of the ClustermeshApiserver server cert
	ClustermeshApiserverServerCertCommonName string
	// ClustermeshApiserverServerCertValidityDuration of certificate
	ClustermeshApiserverServerCertValidityDuration time.Duration
	// ClustermeshApiserverServerCertSecretName where the ClustermeshApiserver server cert and key will be stored
	ClustermeshApiserverServerCertSecretName string

	// ClustermeshApiserverAdminCertCommonName is the CN of the ClustermeshApiserver admin cert
	ClustermeshApiserverAdminCertCommonName string
	// ClustermeshApiserverAdminCertValidityDuration of certificate
	ClustermeshApiserverAdminCertValidityDuration time.Duration
	// ClustermeshApiserverAdminCertSecretName where the ClustermeshApiserver admin cert and key will be stored
	ClustermeshApiserverAdminCertSecretName string

	// ClustermeshApiserverClientCertCommonName is the CN of the ClustermeshApiserver client cert
	ClustermeshApiserverClientCertCommonName string
	// ClustermeshApiserverClientCertValidityDuration of certificate
	ClustermeshApiserverClientCertValidityDuration time.Duration
	// ClustermeshApiserverClientCertSecretName where the ClustermeshApiserver client cert and key will be stored
	ClustermeshApiserverClientCertSecretName string
}

// PopulateFrom populates the config struct with the values provided by vp
func (c *CertGenConfig) PopulateFrom(vp *viper.Viper) {
	c.Debug = vp.GetBool(Debug)
	c.K8sKubeConfigPath = vp.GetString(K8sKubeConfigPath)
	c.K8sRequestTimeout = vp.GetDuration(K8sRequestTimeout)

	c.HubbleCACertFile = vp.GetString(HubbleCACertFile)
	c.HubbleCAKeyFile = vp.GetString(HubbleCAKeyFile)

	c.HubbleCAGenerate = vp.GetBool(HubbleCAGenerate)
	c.HubbleCACommonName = vp.GetString(HubbleCACommonName)
	c.HubbleCAValidityDuration = vp.GetDuration(HubbleCAValidityDuration)
	c.HubbleCAConfigMapName = vp.GetString(HubbleCAConfigMapName)
	c.HubbleCAConfigMapNamespace = vp.GetString(HubbleCAConfigMapNamespace)

	c.HubbleRelayClientCertGenerate = vp.GetBool(HubbleRelayClientCertGenerate)
	c.HubbleRelayClientCertCommonName = vp.GetString(HubbleRelayClientCertCommonName)
	c.HubbleRelayClientCertValidityDuration = vp.GetDuration(HubbleRelayClientCertValidityDuration)
	c.HubbleRelayClientCertSecretName = vp.GetString(HubbleRelayClientCertSecretName)
	c.HubbleRelayClientCertSecretNamespace = vp.GetString(HubbleRelayClientCertSecretNamespace)

	c.HubbleRelayServerCertGenerate = vp.GetBool(HubbleRelayServerCertGenerate)
	c.HubbleRelayServerCertCommonName = vp.GetString(HubbleRelayServerCertCommonName)
	c.HubbleRelayServerCertValidityDuration = vp.GetDuration(HubbleRelayServerCertValidityDuration)
	c.HubbleRelayServerCertSecretName = vp.GetString(HubbleRelayServerCertSecretName)
	c.HubbleRelayServerCertSecretNamespace = vp.GetString(HubbleRelayServerCertSecretNamespace)

	c.HubbleServerCertGenerate = vp.GetBool(HubbleServerCertGenerate)
	c.HubbleServerCertCommonName = vp.GetString(HubbleServerCertCommonName)
	c.HubbleServerCertValidityDuration = vp.GetDuration(HubbleServerCertValidityDuration)
	c.HubbleServerCertSecretName = vp.GetString(HubbleServerCertSecretName)
	c.HubbleServerCertSecretNamespace = vp.GetString(HubbleServerCertSecretNamespace)

	c.CiliumNamespace = vp.GetString(CiliumNamespace)

	c.ClustermeshApiserverCACertFile = vp.GetString(ClustermeshApiserverCACertFile)
	c.ClustermeshApiserverCAKeyFile = vp.GetString(ClustermeshApiserverCAKeyFile)

	c.ClustermeshApiserverCertsGenerate = vp.GetBool(ClustermeshApiserverCertsGenerate)

	c.ClustermeshApiserverCACertCommonName = vp.GetString(ClustermeshApiserverCACertCommonName)
	c.ClustermeshApiserverCACertValidityDuration = vp.GetDuration(ClustermeshApiserverCACertValidityDuration)
	c.ClustermeshApiserverCACertSecretName = vp.GetString(ClustermeshApiserverCACertSecretName)

	c.ClustermeshApiserverServerCertCommonName = vp.GetString(ClustermeshApiserverServerCertCommonName)
	c.ClustermeshApiserverServerCertValidityDuration = vp.GetDuration(ClustermeshApiserverServerCertValidityDuration)
	c.ClustermeshApiserverServerCertSecretName = vp.GetString(ClustermeshApiserverServerCertSecretName)

	c.ClustermeshApiserverAdminCertCommonName = vp.GetString(ClustermeshApiserverAdminCertCommonName)
	c.ClustermeshApiserverAdminCertValidityDuration = vp.GetDuration(ClustermeshApiserverAdminCertValidityDuration)
	c.ClustermeshApiserverAdminCertSecretName = vp.GetString(ClustermeshApiserverAdminCertSecretName)

	c.ClustermeshApiserverClientCertCommonName = vp.GetString(ClustermeshApiserverClientCertCommonName)
	c.ClustermeshApiserverClientCertValidityDuration = vp.GetDuration(ClustermeshApiserverClientCertValidityDuration)
	c.ClustermeshApiserverClientCertSecretName = vp.GetString(ClustermeshApiserverClientCertSecretName)
}
