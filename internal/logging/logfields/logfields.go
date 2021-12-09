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

package logfields

const (
	// LogSubsys is the field denoting the subsystem when logging.
	LogSubsys = "subsys"

	// LogSyslog is the field denoting the syslog level when logging.
	LogSyslog = "syslog"

	// CertCommonName is the field denoting a x509 certificate's CN.
	CertCommonName = "certCommonName"
	// CertValidityDuration is the field denoting a x509 certificate's validity
	// durationg
	CertValidityDuration = "certValidityDuration"
	// CertUsage is the field denoting a x509 certificate's key usages.
	CertUsage = "certUsage"

	// K8sSecretName is the field denoting a Kubernetes secret name.
	K8sSecretName = "k8sSecretName"
	// K8sSecretNamespace is the field denoting a Kubernetes secret's namespace.
	K8sSecretNamespace = "k8sSecretNamespace"
)
