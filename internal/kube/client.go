package kube

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	kubeAPIURL              = "https://kubernetes.default.svc"
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	serviceAccountCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

type kubeAPI struct {
	Client     *http.Client
	BaseURL    string
	AuthHeader string
}

type kubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string `yaml:"token"`
			TokenFile             string `yaml:"tokenFile"`
			ClientCertificate     string `yaml:"client-certificate"`
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKey             string `yaml:"client-key"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

type kubeconfigCluster struct {
	Server                   string
	CertificateAuthority     string
	CertificateAuthorityData string
	InsecureSkipTLSVerify    bool
}

type kubeconfigUser struct {
	Token                 string
	TokenFile             string
	ClientCertificate     string
	ClientCertificateData string
	ClientKey             string
	ClientKeyData         string
}

// kubeAPIClient returns a configured kubeAPI client. It first attempts to find the information as if it was a pod
// if not, then it falls back to looking for a kubeconfig file.
func kubeAPIClient() (kubeAPI, error) {
	if _, tokenErr := os.Stat(serviceAccountTokenPath); tokenErr == nil {
		if _, caErr := os.Stat(serviceAccountCAPath); caErr == nil {
			api, err := inClusterClient()
			if err == nil {
				return api, nil
			}
		}
	}

	return kubeconfigClient()
}

// inClusterClient returns a kubeAPI client configured with the service account token and CA, assuming the process is running inside a Kubernetes cluster.
func inClusterClient() (kubeAPI, error) {
	tokenBytes, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return kubeAPI{}, err
	}

	caBytes, err := os.ReadFile(serviceAccountCAPath)
	if err != nil {
		return kubeAPI{}, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caBytes) {
		return kubeAPI{}, fmt.Errorf("failed to parse kubernetes CA certificate")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
	}

	return kubeAPI{
		Client:     client,
		BaseURL:    kubeAPIURL,
		AuthHeader: "Bearer " + strings.TrimSpace(string(tokenBytes)),
	}, nil
}

// kubeconfigClient returns a kubeAPI client configured based on the kubeconfig file, assuming the process is running outside of a Kubernetes cluster.
func kubeconfigClient() (kubeAPI, error) {
	path, err := discoverKubeconfigPath()
	if err != nil {
		return kubeAPI{}, err
	}

	configBytes, err := os.ReadFile(path)
	if err != nil {
		return kubeAPI{}, fmt.Errorf("failed to read kubeconfig %q: %w", path, err)
	}

	var config kubeconfig
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		return kubeAPI{}, fmt.Errorf("failed to parse kubeconfig %q: %w", path, err)
	}

	clusterName, userName, err := config.resolveContext()
	if err != nil {
		return kubeAPI{}, err
	}

	cluster, err := config.findCluster(clusterName)
	if err != nil {
		return kubeAPI{}, err
	}

	user, err := config.findUser(userName)
	if err != nil {
		return kubeAPI{}, err
	}

	tlsConfig, err := buildTLSConfig(cluster, user, filepath.Dir(path))
	if err != nil {
		return kubeAPI{}, err
	}

	authHeader, err := buildAuthHeader(user, filepath.Dir(path))
	if err != nil {
		return kubeAPI{}, err
	}

	baseURL := strings.TrimSpace(cluster.Server)
	if baseURL == "" {
		return kubeAPI{}, fmt.Errorf("kubeconfig cluster server is empty")
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	return kubeAPI{Client: client, BaseURL: strings.TrimRight(baseURL, "/"), AuthHeader: authHeader}, nil
}

// resolveContext returns the cluster and user names of the kubeconfig context to use, based on the current-context field or defaulting to the first context if current-context is not set.
func (k kubeconfig) resolveContext() (string, string, error) {
	selected := strings.TrimSpace(k.CurrentContext)
	if selected == "" && len(k.Contexts) > 0 {
		selected = strings.TrimSpace(k.Contexts[0].Name)
	}
	if selected == "" {
		return "", "", fmt.Errorf("kubeconfig has no context")
	}

	for _, context := range k.Contexts {
		if strings.TrimSpace(context.Name) == selected {
			cluster := strings.TrimSpace(context.Context.Cluster)
			user := strings.TrimSpace(context.Context.User)
			if cluster == "" {
				return "", "", fmt.Errorf("kubeconfig context %q has no cluster", selected)
			}
			return cluster, user, nil
		}
	}

	return "", "", fmt.Errorf("kubeconfig context %q not found", selected)
}

// findCluster looks up the information of the passed cluster name in the kubeconfig file
func (k kubeconfig) findCluster(name string) (kubeconfigCluster, error) {
	for _, cluster := range k.Clusters {
		if strings.TrimSpace(cluster.Name) == name {
			return kubeconfigCluster{
				Server:                   cluster.Cluster.Server,
				CertificateAuthority:     cluster.Cluster.CertificateAuthority,
				CertificateAuthorityData: cluster.Cluster.CertificateAuthorityData,
				InsecureSkipTLSVerify:    cluster.Cluster.InsecureSkipTLSVerify,
			}, nil
		}
	}

	return kubeconfigCluster{}, fmt.Errorf("kubeconfig cluster %q not found", name)
}

// findUser looks up the information of the passed user name in the kubeconfig file
func (k kubeconfig) findUser(name string) (kubeconfigUser, error) {
	if name == "" {
		return kubeconfigUser{}, nil
	}

	for _, user := range k.Users {
		if strings.TrimSpace(user.Name) == name {
			return kubeconfigUser{
				Token:                 user.User.Token,
				TokenFile:             user.User.TokenFile,
				ClientCertificate:     user.User.ClientCertificate,
				ClientCertificateData: user.User.ClientCertificateData,
				ClientKey:             user.User.ClientKey,
				ClientKeyData:         user.User.ClientKeyData,
			}, nil
		}
	}

	return kubeconfigUser{}, fmt.Errorf("kubeconfig user %q not found", name)
}

// discoverKubeconfigPath tries to find the Kubeconfig file first by checking:
// 1 - KUBECONFIG envvar
// 2 - /etc/rancher/rke2/rke2.yaml (default location for RKE2)
// 3 - ~/.kube/config
func discoverKubeconfigPath() (string, error) {
	candidates := make([]string, 0, 3)

	if configured := strings.TrimSpace(os.Getenv("KUBECONFIG")); configured != "" {
		parts := strings.Split(configured, ":")
		if len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
			candidates = append(candidates, strings.TrimSpace(parts[0]))
		}
	}

	candidates = append(candidates, "/etc/rancher/rke2/rke2.yaml")

	if homeDir, err := os.UserHomeDir(); err == nil && strings.TrimSpace(homeDir) != "" {
		candidates = append(candidates, filepath.Join(homeDir, ".kube", "config"))
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("no kube auth available: service account not found and kubeconfig not found (checked %s)", strings.Join(candidates, ", "))
}

// buildTLSConfig builds a tls.Config for the kube API client to ecnrypt the connection
func buildTLSConfig(cluster kubeconfigCluster, user kubeconfigUser, kubeconfigDir string) (*tls.Config, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: cluster.InsecureSkipTLSVerify}

	if !cluster.InsecureSkipTLSVerify {
		caBytes, err := resolveBytes(cluster.CertificateAuthorityData, cluster.CertificateAuthority, kubeconfigDir)
		if err != nil {
			return nil, fmt.Errorf("failed to load kubeconfig CA: %w", err)
		}
		if len(caBytes) > 0 {
			certPool := x509.NewCertPool()
			if !certPool.AppendCertsFromPEM(caBytes) {
				return nil, fmt.Errorf("failed to parse kubeconfig CA certificate")
			}
			tlsConfig.RootCAs = certPool
		}
	}

	certBytes, certErr := resolveBytes(user.ClientCertificateData, user.ClientCertificate, kubeconfigDir)
	keyBytes, keyErr := resolveBytes(user.ClientKeyData, user.ClientKey, kubeconfigDir)
	if certErr != nil {
		return nil, fmt.Errorf("failed to load kubeconfig client certificate: %w", certErr)
	}
	if keyErr != nil {
		return nil, fmt.Errorf("failed to load kubeconfig client key: %w", keyErr)
	}
	if len(certBytes) > 0 || len(keyBytes) > 0 {
		if len(certBytes) == 0 || len(keyBytes) == 0 {
			return nil, fmt.Errorf("both client certificate and client key must be set in kubeconfig")
		}
		cert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse kubeconfig client cert/key: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// buildAuthHeader builds the bearer token to identify the user to the kube API
func buildAuthHeader(user kubeconfigUser, kubeconfigDir string) (string, error) {
	token := strings.TrimSpace(user.Token)
	if token == "" && strings.TrimSpace(user.TokenFile) != "" {
		tokenFile := user.TokenFile
		if !filepath.IsAbs(tokenFile) {
			tokenFile = filepath.Join(kubeconfigDir, tokenFile)
		}
		tokenBytes, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("failed to read kubeconfig token file %q: %w", tokenFile, err)
		}
		token = strings.TrimSpace(string(tokenBytes))
	}

	if token == "" {
		return "", nil
	}

	return "Bearer " + token, nil
}

// resolveBytes resolves the content of a kubeconfig field that can be either inline (base64) or a file reference
func resolveBytes(embeddedData string, filePath string, baseDir string) ([]byte, error) {
	trimmedData := strings.TrimSpace(embeddedData)
	if trimmedData != "" {
		decoded, err := base64.StdEncoding.DecodeString(trimmedData)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	}

	trimmedPath := strings.TrimSpace(filePath)
	if trimmedPath == "" {
		return nil, nil
	}

	if !filepath.IsAbs(trimmedPath) {
		trimmedPath = filepath.Join(baseDir, trimmedPath)
	}

	bytes, err := os.ReadFile(trimmedPath)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}
