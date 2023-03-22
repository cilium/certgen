// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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

// New creates and returns a certgen command.
func New() (*cobra.Command, error) {
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

	flags.String(option.CACertFile, "", "Path to provided Cilium CA certificate file (required if Cilium CA is not generated)")
	flags.String(option.CAKeyFile, "", "Path to provided Cilium CA key file (required if Cilium CA is not generated)")

	flags.Bool(option.CAGenerate, defaults.CAGenerate, "Generate and store Cilium CA certificate")
	flags.Bool(option.CAReuseSecret, defaults.CAReuseSecret, "Reuse the Cilium CA secret if it exists, otherwise generate a new one")
	flags.String(option.CACommonName, defaults.CACommonName, "Cilium CA common name")
	flags.Duration(option.CAValidityDuration, defaults.CAValidityDuration, "Cilium CA validity duration")
	flags.String(option.CASecretName, defaults.CASecretName, "Name of the K8s Secret where the Cilium CA cert and key are stored in")
	flags.String(option.CASecretNamespace, "", "Overwrites the namespace of the K8s Secret where the Cilium CA cert and key are stored in")

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

	flags.Bool(option.ClustermeshApiserverServerCertGenerate, defaults.ClustermeshApiserverServerCertGenerate, "Generate and store clustermesh-apiserver server certificate")
	flags.String(option.ClustermeshApiserverServerCertCommonName, defaults.ClustermeshApiserverServerCertCommonName, "clustermesh-apiserver server certificate common name")
	flags.Duration(option.ClustermeshApiserverServerCertValidityDuration, defaults.ClustermeshApiserverServerCertValidityDuration, "clustermesh-apiserver server certificate validity duration")
	flags.String(option.ClustermeshApiserverServerCertSecretName, defaults.ClustermeshApiserverServerCertSecretName, "Name of the K8s Secret where the clustermesh-apiserver server cert and key are stored in")
	flags.StringSlice(option.ClustermeshApiserverServerCertSANs, defaults.ClustermeshApiserverServerCertSANs, "clustermesh-apiserver server certificate SANs")

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

	if err := vp.BindPFlags(flags); err != nil {
		return nil, err
	}

	return rootCmd, nil
}

// Execute runs the root command. This is called by main.main().
func Execute() error {
	cmd, err := New()
	if err != nil {
		return err
	}
	return cmd.Execute()
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

	// Store after all the requested certs have been successfully generated
	count := 0

	ciliumCA := generate.NewCA(option.Config.CASecretName, option.Config.CASecretNamespace)

	if option.Config.CAGenerate {
		err = ciliumCA.Generate(option.Config.CACommonName, option.Config.CAValidityDuration)
		if err != nil {
			return fmt.Errorf("failed to generate Cilium CA: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()

		err = ciliumCA.StoreAsSecret(ctx, k8sClient, !option.Config.CAReuseSecret)
		if err != nil {
			if !k8sErrors.IsAlreadyExists(err) || !option.Config.CAReuseSecret {
				return fmt.Errorf("failed to create secret for Cilium CA: %w", err)
			}
			// reset so that we can re-load later as CAReuseSecret is true
			ciliumCA.Reset()
		} else {
			count++
		}
	} else if option.Config.CACertFile != "" && option.Config.CAKeyFile != "" {
		log.Info("Loading Cilium CA from file")
		err = ciliumCA.LoadFromFile(option.Config.CACertFile, option.Config.CAKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load Cilium CA from file: %w", err)
		}
	}

	if ciliumCA.IsEmpty() && option.Config.CAReuseSecret {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		err = ciliumCA.LoadFromSecret(ctx, k8sClient)
		if err != nil {
			return fmt.Errorf("failed to load Cilium CA from secret: %w", err)
		}
		log.Info("Loaded Cilium CA Secret")
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
		err := hubbleServerCert.Generate(ciliumCA)
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
		err := hubbleRelayClientCert.Generate(ciliumCA)
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
		err := hubbleRelayServerCert.Generate(ciliumCA)
		if err != nil {
			return fmt.Errorf("failed to generate Hubble Relay server cert: %w", err)
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
		).WithHosts(
			append([]string{
				option.Config.ClustermeshApiserverServerCertCommonName,
				"127.0.0.1",
			}, option.Config.ClustermeshApiserverServerCertSANs...),
		)
		err = clustermeshApiserverServerCert.Generate(ciliumCA)
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
		err = clustermeshApiserverAdminCert.Generate(ciliumCA)
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
		err = clustermeshApiserverClientCert.Generate(ciliumCA)
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
		err = clustermeshApiserverRemoteCert.Generate(ciliumCA)
		if err != nil {
			return fmt.Errorf("failed to generate ClustermeshApiserver remote cert: %w", err)
		}
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
