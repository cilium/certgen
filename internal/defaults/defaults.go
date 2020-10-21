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

package defaults

import "time"

const (
	Debug = false

	HubbleCAGenerate           = false
	HubbleCACommonName         = "hubble-ca.cilium.io"
	HubbleCAValidityDuration   = 3 * 365 * 24 * time.Hour
	HubbleCAConfigMapName      = "hubble-ca-cert"
	HubbleCAConfigMapNamespace = "kube-system"

	HubbleServerCertGenerate         = false
	HubbleServerCertCommonName       = "*.default.hubble-grpc.cilium.io"
	HubbleServerCertValidityDuration = 3 * 365 * 24 * time.Hour
	HubbleServerCertSecretName       = "hubble-server-certs"
	HubbleServerCertSecretNamespace  = "kube-system"

	HubbleRelayServerCertGenerate         = false
	HubbleRelayServerCertCommonName       = "*.hubble-relay.cilium.io"
	HubbleRelayServerCertValidityDuration = 3 * 365 * 24 * time.Hour
	HubbleRelayServerCertSecretName       = "hubble-relay-server-certs"
	HubbleRelayServerCertSecretNamespace  = "kube-system"

	HubbleRelayClientCertGenerate         = false
	HubbleRelayClientCertCommonName       = "*.hubble-relay.cilium.io"
	HubbleRelayClientCertValidityDuration = 3 * 365 * 24 * time.Hour
	HubbleRelayClientCertSecretName       = "hubble-relay-client-certs"
	HubbleRelayClientCertSecretNamespace  = "kube-system"

	CiliumNamespace = "kube-system"

	ExternalWorkloadCertsGenerate = false

	ExternalWorkloadCACertCommonName       = "externalworkload-ca.cilium.io"
	ExternalWorkloadCACertValidityDuration = 3 * 365 * 24 * time.Hour
	ExternalWorkloadCACertSecretName       = "externalworkload-ca-cert"

	ExternalWorkloadServerCertCommonName       = "clustermesh-apiserver.cilium.io"
	ExternalWorkloadServerCertValidityDuration = 3 * 365 * 24 * time.Hour
	ExternalWorkloadServerCertSecretName       = "externalworkload-server-certs"

	ExternalWorkloadAdminCertCommonName       = "root"
	ExternalWorkloadAdminCertValidityDuration = 3 * 365 * 24 * time.Hour
	ExternalWorkloadAdminCertSecretName       = "externalworkload-admin-certs"

	ExternalWorkloadClientCertCommonName       = "externalworkload"
	ExternalWorkloadClientCertValidityDuration = 3 * 365 * 24 * time.Hour
	ExternalWorkloadClientCertSecretName       = "externalworkload-client-certs"

	K8sRequestTimeout = 60 * time.Second
)

var (
	HubbleServerCertUsage      = []string{"signing", "key encipherment", "server auth"}
	HubbleRelayServerCertUsage = []string{"signing", "key encipherment", "server auth"}
	HubbleRelayClientCertUsage = []string{"signing", "key encipherment", "server auth", "client auth"}

	ExternalWorkloadCertUsage = []string{"signing", "key encipherment", "server auth", "client auth"}
)
