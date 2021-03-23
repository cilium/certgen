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

package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/cilium/certgen/internal/defaults"
	"github.com/cilium/certgen/internal/generate"
	"github.com/cilium/certgen/internal/logging"
	"github.com/cilium/certgen/internal/logging/logfields"
	"github.com/cilium/certgen/internal/option"
	"github.com/cilium/certgen/internal/version"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const binaryName = "cilium-certgen"

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, binaryName)

func New() *cobra.Command {
	vp := viper.New()
	rootCmd := &cobra.Command{
		Use:           binaryName + " [flags]",
		Short:         binaryName,
		Long:          binaryName + " bootstraps TLS certificates and stores them as K8s secrets",
		SilenceErrors: true,
		Version:       version.Version,
		Run: func(cmd *cobra.Command, args []string) {
			option.Config.PopulateFrom(vp)

			if option.Config.Debug {
				logging.DefaultLogger.SetLevel(logrus.DebugLevel)
			}

			log.Infof("%s %s", binaryName, version.Version)

			if err := generateCertificates(); err != nil {
				log.WithError(err).Fatal("failed to generate certificates")
			}
		},
	}
	rootCmd.SetVersionTemplate("{{with .Name}}{{printf \"%s \" .}}{{end}}{{printf \"v%s\" .Version}}\n")

	flags := rootCmd.Flags()
	flags.BoolP(option.Debug, "D", defaults.Debug, "Enable debug messages")

	flags.String(option.K8sKubeConfigPath, "", "Path to the K8s kubeconfig file. If absent, the in-cluster config is used.")
	flags.Duration(option.K8sRequestTimeout, defaults.K8sRequestTimeout, "Timeout for K8s API requests")

	flags.String(option.HubbleCACertFile, "", "Path to provided Hubble CA certificate file (required if Hubble CA is not generated)")
	flags.String(option.HubbleCAKeyFile, "", "Path to provided Hubble CA key file (required if Hubble CA is not generated)")

	flags.Bool(option.HubbleCAGenerate, defaults.HubbleCAGenerate, "Generate and store Hubble CA certificate")
	flags.Bool(option.HubbleCAReuseSecret, defaults.HubbleCAReuseSecret, "Reuse the Hubble CA secret if it exists, otherwise generate a new one")
	flags.String(option.HubbleCACommonName, defaults.HubbleCACommonName, "Hubble CA common name")
	flags.Duration(option.HubbleCAValidityDuration, defaults.HubbleCAValidityDuration, "Hubble CA validity duration")
	flags.String(option.HubbleCASecretName, defaults.HubbleCASecretName, "Name of the K8s Secret where the Hubble CA cert and key are stored in")
	flags.String(option.HubbleCASecretNamespace, "", "Overwrites the namespace of the K8s Secret where the Hubble CA cert and key are stored in")

	flags.Bool(option.HubbleCAConfigMapCreate, defaults.HubbleCAConfigMapCreate, "Store the Hubble CA cert additionally in a K8s ConfigMap")
	flags.String(option.HubbleCAConfigMapName, defaults.HubbleCAConfigMapName, "Name of the K8s ConfigMap where the Hubble CA cert is stored in")
	flags.String(option.HubbleCAConfigMapNamespace, "", "Overwrites the namespace of the ConfigMap where the Hubble CA cert is stored in")

	flags.Bool(option.HubbleRelayClientCertGenerate, defaults.HubbleRelayClientCertGenerate, "Generate and store Hubble Relay client certificate")
	flags.String(option.HubbleRelayClientCertCommonName, defaults.HubbleRelayClientCertCommonName, "Hubble Relay client certificate common name")
	flags.Duration(option.HubbleRelayClientCertValidityDuration, defaults.HubbleRelayClientCertValidityDuration, "Hubble Relay client certificate validity duration")
	flags.String(option.HubbleRelayClientCertSecretName, defaults.HubbleRelayClientCertSecretName, "Name of the K8s Secret where the Hubble Relay client cert and key are stored in")
	flags.String(option.HubbleRelayClientCertSecretNamespace, "", "Overwrites the namespace of the K8s Secret where the Hubble Relay client cert and key are stored in")

	flags.Bool(option.HubbleRelayServerCertGenerate, defaults.HubbleRelayServerCertGenerate, "Generate and store Hubble Relay server certificate")
	flags.String(option.HubbleRelayServerCertCommonName, defaults.HubbleRelayServerCertCommonName, "Hubble Relay server certificate common name")
	flags.Duration(option.HubbleRelayServerCertValidityDuration, defaults.HubbleRelayServerCertValidityDuration, "Hubble Relay server certificate validity duration")
	flags.String(option.HubbleRelayServerCertSecretName, defaults.HubbleRelayServerCertSecretName, "Name of the K8s Secret where the Hubble Relay server cert and key are stored in")
	flags.String(option.HubbleRelayServerCertSecretNamespace, "", "Overwrites the namespace of the K8s Secret where the Hubble Relay server cert and key are stored in")

	flags.Bool(option.HubbleServerCertGenerate, defaults.HubbleServerCertGenerate, "Generate and store Hubble server certificate")
	flags.String(option.HubbleServerCertCommonName, defaults.HubbleServerCertCommonName, "Hubble server certificate common name")
	flags.Duration(option.HubbleServerCertValidityDuration, defaults.HubbleServerCertValidityDuration, "Hubble server certificate validity duration")
	flags.String(option.HubbleServerCertSecretName, defaults.HubbleServerCertSecretName, "Name of the K8s Secret where the Hubble server cert and key are stored in")
	flags.String(option.HubbleServerCertSecretNamespace, "", "Overwrites the namespace of the K8s Secret where the Hubble server cert and key are stored in")

	// Extenal Workload certs
	flags.String(option.CiliumNamespace, defaults.CiliumNamespace, "Namespace where the cert secrets and configmaps are stored in")

	flags.String(option.ClustermeshApiserverCACertFile, "", "Path to provided clustermesh-apiserver CA certificate file (required if CA does not exist and is not to be generated)")
	flags.String(option.ClustermeshApiserverCAKeyFile, "", "Path to provided clustermesh-apiserver CA key file (required if CA does not exist and is not to be generated)")

	flags.Bool(option.ClustermeshApiserverCACertGenerate, defaults.ClustermeshApiserverCACertGenerate, "Generate and store clustermesh-apiserver CA certificate")
	flags.Bool(option.ClustermeshApiserverCACertReuseSecret, defaults.ClustermeshApiserverCACertReuseSecret, "Reuse the clustermesh-apiserver CA secret if it exists, otherwise generate a new one")
	flags.String(option.ClustermeshApiserverCACertCommonName, defaults.ClustermeshApiserverCACertCommonName, "clustermesh-apiserver CA certificate common name")
	flags.Duration(option.ClustermeshApiserverCACertValidityDuration, defaults.ClustermeshApiserverCACertValidityDuration, "clustermesh-apiserver CA certificate validity duration")
	flags.String(option.ClustermeshApiserverCACertSecretName, defaults.ClustermeshApiserverCACertSecretName, "Name of the K8s Secret where the clustermesh-apiserver CA cert is stored in")

	flags.Bool(option.ClustermeshApiserverServerCertGenerate, defaults.ClustermeshApiserverServerCertGenerate, "Generate and store clustermesh-apiserver server certificate")
	flags.String(option.ClustermeshApiserverServerCertCommonName, defaults.ClustermeshApiserverServerCertCommonName, "clustermesh-apiserver server certificate common name")
	flags.Duration(option.ClustermeshApiserverServerCertValidityDuration, defaults.ClustermeshApiserverServerCertValidityDuration, "clustermesh-apiserver server certificate validity duration")
	flags.String(option.ClustermeshApiserverServerCertSecretName, defaults.ClustermeshApiserverServerCertSecretName, "Name of the K8s Secret where the clustermesh-apiserver server cert and key are stored in")

	flags.Bool(option.ClustermeshApiserverAdminCertGenerate, defaults.ClustermeshApiserverAdminCertGenerate, "Generate and store clustermesh-apiserver admin certificate")
	flags.String(option.ClustermeshApiserverAdminCertCommonName, defaults.ClustermeshApiserverAdminCertCommonName, "clustermesh-apiserver admin certificate common name")
	flags.Duration(option.ClustermeshApiserverAdminCertValidityDuration, defaults.ClustermeshApiserverAdminCertValidityDuration, "clustermesh-apiserver admin certificate validity duration")
	flags.String(option.ClustermeshApiserverAdminCertSecretName, defaults.ClustermeshApiserverAdminCertSecretName, "Name of the K8s Secret where the clustermesh-apiserver admin cert and key are stored in")

	flags.Bool(option.ClustermeshApiserverClientCertGenerate, defaults.ClustermeshApiserverClientCertGenerate, "Generate and store clustermesh-apiserver client certificate")
	flags.String(option.ClustermeshApiserverClientCertCommonName, defaults.ClustermeshApiserverClientCertCommonName, "clustermesh-apiserver client certificate common name")
	flags.Duration(option.ClustermeshApiserverClientCertValidityDuration, defaults.ClustermeshApiserverClientCertValidityDuration, "clustermesh-apiserver client certificate validity duration")
	flags.String(option.ClustermeshApiserverClientCertSecretName, defaults.ClustermeshApiserverClientCertSecretName, "Name of the K8s Secret where the clustermesh-apiserver client cert and key are stored in")

	flags.Bool(option.ClustermeshApiserverRemoteCertGenerate, defaults.ClustermeshApiserverRemoteCertGenerate, "Generate and store clustermesh-apiserver remote certificate")
	flags.String(option.ClustermeshApiserverRemoteCertCommonName, defaults.ClustermeshApiserverRemoteCertCommonName, "clustermesh-apiserver remote certificate common name")
	flags.Duration(option.ClustermeshApiserverRemoteCertValidityDuration, defaults.ClustermeshApiserverRemoteCertValidityDuration, "clustermesh-apiserver remote certificate validity duration")
	flags.String(option.ClustermeshApiserverRemoteCertSecretName, defaults.ClustermeshApiserverRemoteCertSecretName, "Name of the K8s Secret where the clustermesh-apiserver remote cert and key are stored in")

	// Sets up viper to read in flags via CILIUM_CERTGEN_ env variables
	vp.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	vp.SetEnvPrefix(binaryName)
	vp.AutomaticEnv()
	vp.BindPFlags(flags)

	return rootCmd
}

// Execute runs the root command. This is called by main.main().
func Execute() error {
	return New().Execute()
}

// k8sConfig creates a new Kubernetes config either based on the provided
// kubeconfig file or alternatively the in-cluster configuration.
func k8sConfig(kubeconfig string) (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error
	if kubeconfig == "" {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

// generateCertificates runs the main code to generate and store certificate
func generateCertificates() error {
	k8sClient, err := k8sConfig(option.Config.K8sKubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed initialize kubernetes client: %w", err)
	}

	hubbleCA := generate.NewCA(option.Config.HubbleCASecretName, option.Config.HubbleCASecretNamespace)
	if option.Config.HubbleCAConfigMapCreate {
		hubbleCA.ConfigMapName = option.Config.HubbleCAConfigMapName
		hubbleCA.ConfigMapNamespace = option.Config.HubbleCAConfigMapNamespace
	}

	if option.Config.HubbleCAReuseSecret {
		// Read CA from Secret if it already exists
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		err = hubbleCA.LoadFromSecret(ctx, k8sClient)
		if err != nil {
			if k8sErrors.IsNotFound(err) && option.Config.HubbleCAGenerate {
				log.Info("Hubble CA secret does not exist, generating new CA")
			} else {
				// Permission error or something like that
				return fmt.Errorf("failed to load Hubble CA from secret: %w", err)
			}
		}
		log.Info("Loaded Hubble CA Secret")
	}

	// Generate a CA only if we were not able to load it from secret
	if option.Config.HubbleCAGenerate && !hubbleCA.LoadedFromSecret() {
		err = hubbleCA.Generate(option.Config.HubbleCACommonName, option.Config.HubbleCAValidityDuration)
		if err != nil {
			return fmt.Errorf("failed to generate Hubble CA: %w", err)
		}
	} else if option.Config.HubbleCACertFile != "" && option.Config.HubbleCAKeyFile != "" {
		log.Info("Loading Hubble CA from file")
		err = hubbleCA.LoadFromFile(option.Config.HubbleCACertFile, option.Config.HubbleCAKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load Hubble CA from file: %w", err)
		}
	}

	var hubbleServerCert *generate.Cert
	if option.Config.HubbleServerCertGenerate {
		log.Info("Generating server certificates for Hubble")
		hubbleServerCert = generate.NewCert(
			option.Config.HubbleServerCertCommonName,
			option.Config.HubbleServerCertValidityDuration,
			defaults.HubbleServerCertUsage,
			option.Config.HubbleServerCertSecretName,
			option.Config.HubbleServerCertSecretNamespace,
		)
		err := hubbleServerCert.Generate(hubbleCA)
		if err != nil {
			return fmt.Errorf("failed to generate Hubble server cert: %w", err)
		}
	}

	var hubbleRelayClientCert *generate.Cert
	if option.Config.HubbleRelayClientCertGenerate {
		log.Info("Generating client certificates for Hubble Relay")
		hubbleRelayClientCert = generate.NewCert(
			option.Config.HubbleRelayClientCertCommonName,
			option.Config.HubbleRelayClientCertValidityDuration,
			defaults.HubbleRelayClientCertUsage,
			option.Config.HubbleRelayClientCertSecretName,
			option.Config.HubbleRelayClientCertSecretNamespace,
		)
		err := hubbleRelayClientCert.Generate(hubbleCA)
		if err != nil {
			return fmt.Errorf("failed to generate Hubble Relay client cert: %w", err)
		}
	}

	var hubbleRelayServerCert *generate.Cert
	if option.Config.HubbleRelayServerCertGenerate {
		log.Info("Generating server certificates for Hubble Relay")
		hubbleRelayServerCert = generate.NewCert(
			option.Config.HubbleRelayServerCertCommonName,
			option.Config.HubbleRelayServerCertValidityDuration,
			defaults.HubbleRelayServerCertUsage,
			option.Config.HubbleRelayServerCertSecretName,
			option.Config.HubbleRelayServerCertSecretNamespace,
		)
		err := hubbleRelayServerCert.Generate(hubbleCA)
		if err != nil {
			return fmt.Errorf("failed to generate Hubble Relay server cert: %w", err)
		}
	}

	clustermeshApiserverCA := generate.NewCA(option.Config.ClustermeshApiserverCACertSecretName, option.Config.CiliumNamespace)
	if option.Config.ClustermeshApiserverCAReuseSecret {
		// Read CA from Secret if it already exists
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		err = clustermeshApiserverCA.LoadFromSecret(ctx, k8sClient)
		if err != nil {
			if k8sErrors.IsNotFound(err) && option.Config.ClustermeshApiserverCACertGenerate {
				log.Info("ClustermeshApiserver CA secret does not exist, generating new CA")
			} else {
				// Permission error or something like that
				return fmt.Errorf("failed to load ClustermeshApiserver CA from secret: %w", err)
			}
		}
		log.Info("Loaded ClustermeshApiserver CA Secret")
	}

	// Generate a CA only if we were not able to load it from secret
	if option.Config.ClustermeshApiserverCACertGenerate && !clustermeshApiserverCA.LoadedFromSecret() {
		err = clustermeshApiserverCA.Generate(option.Config.ClustermeshApiserverCACertCommonName, option.Config.ClustermeshApiserverCACertValidityDuration)
		if err != nil {
			return fmt.Errorf("failed to generate ClustermeshApiserver CA: %w", err)
		}
	} else if option.Config.ClustermeshApiserverCACertFile != "" && option.Config.ClustermeshApiserverCAKeyFile != "" {
		log.Info("Loading ClustermeshApiserver CA from file")
		err = clustermeshApiserverCA.LoadFromFile(option.Config.ClustermeshApiserverCACertFile, option.Config.ClustermeshApiserverCAKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load ClustermeshApiserver CA from file: %w", err)
		}
	}

	var clustermeshApiserverServerCert *generate.Cert
	if option.Config.ClustermeshApiserverServerCertGenerate {
		log.Info("Generating server certificate for ClustermeshApiserver")
		clustermeshApiserverServerCert = generate.NewCert(
			option.Config.ClustermeshApiserverServerCertCommonName,
			option.Config.ClustermeshApiserverServerCertValidityDuration,
			defaults.ClustermeshApiserverCertUsage,
			option.Config.ClustermeshApiserverServerCertSecretName,
			option.Config.CiliumNamespace,
		).WithHosts([]string{option.Config.ClustermeshApiserverServerCertCommonName, "127.0.0.1"})
		err = clustermeshApiserverServerCert.Generate(clustermeshApiserverCA)
		if err != nil {
			return fmt.Errorf("failed to generate ClustermeshApiserver server cert: %w", err)
		}
	}

	var clustermeshApiserverAdminCert *generate.Cert
	if option.Config.ClustermeshApiserverAdminCertGenerate {
		log.Info("Generating admin certificate for ClustermeshApiserver")
		clustermeshApiserverAdminCert = generate.NewCert(
			option.Config.ClustermeshApiserverAdminCertCommonName,
			option.Config.ClustermeshApiserverAdminCertValidityDuration,
			defaults.ClustermeshApiserverCertUsage,
			option.Config.ClustermeshApiserverAdminCertSecretName,
			option.Config.CiliumNamespace,
		).WithHosts([]string{"localhost"})
		err = clustermeshApiserverAdminCert.Generate(clustermeshApiserverCA)
		if err != nil {
			return fmt.Errorf("failed to generate ClustermeshApiserver admin cert: %w", err)
		}
	}

	var clustermeshApiserverClientCert *generate.Cert
	if option.Config.ClustermeshApiserverClientCertGenerate {
		log.Info("Generating client certificate for ClustermeshApiserver")
		clustermeshApiserverClientCert = generate.NewCert(
			option.Config.ClustermeshApiserverClientCertCommonName,
			option.Config.ClustermeshApiserverClientCertValidityDuration,
			defaults.ClustermeshApiserverCertUsage,
			option.Config.ClustermeshApiserverClientCertSecretName,
			option.Config.CiliumNamespace,
		)
		err = clustermeshApiserverClientCert.Generate(clustermeshApiserverCA)
		if err != nil {
			return fmt.Errorf("failed to generate ClustermeshApiserver client cert: %w", err)
		}
	}

	var clustermeshApiserverRemoteCert *generate.Cert
	if option.Config.ClustermeshApiserverRemoteCertGenerate {
		log.Info("Generating remote certificate for ClustermeshApiserver")
		clustermeshApiserverRemoteCert = generate.NewCert(
			option.Config.ClustermeshApiserverRemoteCertCommonName,
			option.Config.ClustermeshApiserverRemoteCertValidityDuration,
			defaults.ClustermeshApiserverCertUsage,
			option.Config.ClustermeshApiserverRemoteCertSecretName,
			option.Config.CiliumNamespace,
		)
		err = clustermeshApiserverRemoteCert.Generate(clustermeshApiserverCA)
		if err != nil {
			return fmt.Errorf("failed to generate ClustermeshApiserver remote cert: %w", err)
		}
	}

	// Store after all the requested certs have been successfully generated
	count := 0

	if option.Config.HubbleCAGenerate && !hubbleCA.LoadedFromSecret() {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := hubbleCA.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for Hubble CA: %w", err)
		}
		count++
	}

	if option.Config.HubbleCAConfigMapCreate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := hubbleCA.StoreAsConfigMap(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create configmap for Hubble CA: %w", err)
		}
		count++
	}

	if option.Config.HubbleServerCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := hubbleServerCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for Hubble server cert: %w", err)
		}
		count++
	}

	if option.Config.HubbleRelayClientCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := hubbleRelayClientCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for Hubble Relay client cert: %w", err)
		}
		count++
	}

	if option.Config.HubbleRelayServerCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := hubbleRelayServerCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for Hubble Relay server cert: %w", err)
		}
		count++
	}

	if option.Config.ClustermeshApiserverCACertGenerate && !clustermeshApiserverCA.LoadedFromSecret() {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := clustermeshApiserverCA.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for ClustermeshApiserver CA: %w", err)
		}
		count++
	}

	if option.Config.ClustermeshApiserverServerCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := clustermeshApiserverServerCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for ClustermeshApiserver server cert: %w", err)
		}
		count++
	}

	if option.Config.ClustermeshApiserverAdminCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := clustermeshApiserverAdminCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for ClustermeshApiserver admin cert: %w", err)
		}
		count++
	}

	if option.Config.ClustermeshApiserverClientCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := clustermeshApiserverClientCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for ClustermeshApiserver client cert: %w", err)
		}
		count++
	}

	if option.Config.ClustermeshApiserverRemoteCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := clustermeshApiserverRemoteCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for ClustermeshApiserver remote cert: %w", err)
		}
		count++
	}

	log.Infof("Successfully generated all %d requested certificates.", count)

	return nil
}
