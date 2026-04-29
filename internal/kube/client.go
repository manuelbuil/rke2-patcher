package kube

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ClientsetProvider returns a Kubernetes clientset using in-cluster config if available, otherwise falls back to kubeconfig.
func ClientsetProvider() (*kubernetes.Clientset, error) {
	// Try in-cluster config
	config, err := rest.InClusterConfig()
	if err == nil {
		clientset, err := kubernetes.NewForConfig(config)
		if err == nil {
			return clientset, nil
		}
		return nil, fmt.Errorf("failed to create clientset from in-cluster config: %w", err)
	}

	// Fallback to kubeconfig
	kubeconfigPath, err := discoverKubeconfigPath()
	if err != nil {
		return nil, fmt.Errorf("could not find kubeconfig: %w", err)
	}
	config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to build config from kubeconfig: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset from kubeconfig: %w", err)
	}
	return clientset, nil
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

	return "", fmt.Errorf("no kubeconfig found (checked %s)", strings.Join(candidates, ", "))
}
