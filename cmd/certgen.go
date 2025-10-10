// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/certgen/internal/defaults"
	"github.com/cilium/certgen/internal/generate"
	"github.com/cilium/certgen/internal/logging"
	"github.com/cilium/certgen/internal/logging/logfields"
	"github.com/cilium/certgen/internal/option"
	"github.com/cilium/certgen/internal/version"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const binaryName = "cilium-certgen"

var log = logging.DefaultLogger.With(slog.String(logfields.LogSubsys, binaryName))

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
				logging.Level.Set(slog.LevelDebug)
			}

			log.Info("Running...",
				"version", version.Version,
			)

			if err := generateCertificates(); err != nil {
				log.Error("failed to generate certificates", "error", err)
			}
		},
	}
	rootCmd.SetVersionTemplate("{{with .Name}}{{printf \"%s \" .}}{{end}}{{printf \"v%s\" .Version}}\n")

	flags := rootCmd.Flags()
	flags.BoolP(option.Debug, "D", defaults.Debug, "Enable debug messages")

	flags.String(option.K8sKubeConfigPath, "", "Path to the K8s kubeconfig file. If absent, the in-cluster config is used.")
	flags.Duration(option.K8sRequestTimeout, defaults.K8sRequestTimeout, "Timeout for K8s API requests")

	flags.String(option.CACertFile, "", "Path to the provided CA certificate file (required if the CA is not generated)")
	flags.String(option.CAKeyFile, "", "Path to the provided CA key file (required if the CA is not generated)")

	flags.Bool(option.CAGenerate, defaults.CAGenerate, "Generate and store the CA certificate")
	flags.Bool(option.CAReuseSecret, defaults.CAReuseSecret, "Reuse the CA secret if it exists, otherwise generate a new one")
	flags.String(option.CACommonName, defaults.CACommonName, "CA common name")
	flags.Duration(option.CAValidityDuration, defaults.CAValidityDuration, "CA validity duration")
	flags.String(option.CASecretName, defaults.CASecretName, "Name of the K8s Secret where the CA cert and key are stored in")
	flags.String(option.CASecretNamespace, defaults.CASecretNamespace, "Namespace of the K8s Secret where the CA cert and key are stored in")

	flags.String(option.CertsConfig, "", "YAML configuration of the certificates to generate, takes precedence over "+option.CertsConfigFile)
	flags.String(option.CertsConfigFile, "", "Path to the file containing the YAML configuration of the certificates to generate")

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

func parseCertificateConfigs(cfg, cfgfile string) (certConfigs option.CertificateConfigs, err error) {
	if cfg == "" && cfgfile == "" {
		return option.CertificateConfigs{}, nil
	}

	data := []byte(cfg)
	if cfg == "" {
		data, err = os.ReadFile(filepath.Clean(cfgfile))
		if err != nil {
			return option.CertificateConfigs{}, fmt.Errorf("failed to read certificates configuration file: %w", err)
		}
	}

	if err = yaml.Unmarshal(data, &certConfigs); err != nil {
		return option.CertificateConfigs{}, fmt.Errorf("failed to parse certificates configuration: %w", err)
	}

	return certConfigs, nil
}

// generateCertificates runs the main code to generate and store certificate
func generateCertificates() error {
	k8sClient, err := k8sConfig(option.Config.K8sKubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed initialize kubernetes client: %w", err)
	}

	certConfigs, err := parseCertificateConfigs(option.Config.CertsConfig, option.Config.CertsConfigFile)
	if err != nil {
		return err
	}

	// Store after all the requested certs have been successfully generated
	count := 0

	ca := generate.NewCA(option.Config.CASecretName, option.Config.CASecretNamespace)

	if option.Config.CAGenerate {
		err = ca.Generate(option.Config.CACommonName, option.Config.CAValidityDuration)
		if err != nil {
			return fmt.Errorf("failed to generate CA: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()

		err = ca.StoreAsSecret(ctx, k8sClient, !option.Config.CAReuseSecret)
		if err != nil {
			if !k8sErrors.IsAlreadyExists(err) || !option.Config.CAReuseSecret {
				return fmt.Errorf("failed to create secret for CA: %w", err)
			}
			// reset so that we can re-load later as CAReuseSecret is true
			ca.Reset()
		} else {
			count++
		}
	} else if option.Config.CACertFile != "" && option.Config.CAKeyFile != "" {
		log.Info("Loading CA from file")
		err = ca.LoadFromFile(option.Config.CACertFile, option.Config.CAKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load CA from file: %w", err)
		}
	}

	if ca.IsEmpty() && option.Config.CAReuseSecret {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		err = ca.LoadFromSecret(ctx, k8sClient)
		if err != nil {
			return fmt.Errorf("failed to load CA from secret: %w", err)
		}
		log.Info("Loaded CA Secret")
	}

	log.Info("Generating certificates")
	certs := make([]*generate.Cert, len(certConfigs.Certs))
	for i, cfg := range certConfigs.Certs {
		log.Info("Generating certificate",
			logfields.K8sSecretName, cfg.Name,
			logfields.K8sSecretNamespace, cfg.Namespace,
		)

		certs[i] = generate.NewCert(
			cfg.CommonName,
			cfg.Validity,
			cfg.Usage,
			cfg.Name,
			cfg.Namespace,
		).WithHosts(cfg.Hosts)

		err := certs[i].Generate(ca)
		if err != nil {
			return fmt.Errorf("failed to generate cert: %w", err)
		}
	}

	log.Info("Storing certificates")
	for _, cert := range certs {
		log.Info("Storing certificate",
			logfields.K8sSecretName, cert.Name,
			logfields.K8sSecretNamespace, cert.Namespace,
		)

		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := cert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}

		count++
	}

	log.Info("Successfully generated all requested certificates.", "count", count)

	return nil
}
