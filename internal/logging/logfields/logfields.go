// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logfields

const (
	// LogSubsys is the field denoting the subsystem when logging.
	LogSubsys = "subsys"

	// LogSyslog is the field denoting the syslog level when logging.
	LogSyslog = "syslog"

	// CertCommonName is the field denoting a x509 certificate's CN.
	CertCommonName = "certCommonName"
	// CertValidityDuration is the field denoting a x509 certificate's validity
	// duration.
	CertValidityDuration = "certValidityDuration"
	// CertUsage is the field denoting a x509 certificate's key usages.
	CertUsage = "certUsage"

	// K8sSecretName is the field denoting a Kubernetes secret name.
	K8sSecretName = "k8sSecretName"
	// K8sSecretNamespace is the field denoting a Kubernetes secret's namespace.
	K8sSecretNamespace = "k8sSecretNamespace"

	// K8sConfigMapName is the field denoting a Kubernetes ConfigMap name.
	K8sConfigMapName = "k8sConfigMapName"
	// K8sConfigMapNamespace is the field denoting a Kubernetes ConfigMap's
	// namespace.
	K8sConfigMapNamespace = "k8sConfigMapNamespace"
)
