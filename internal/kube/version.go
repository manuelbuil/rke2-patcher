package kube

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

// ClusterVersion retrieves the Kubernetes cluster version by querying the kube API server
func ClusterVersion() (string, error) {
	// Try in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig
		kubeconfigPath := os.Getenv("KUBECONFIG")
		if kubeconfigPath == "" {
			kubeconfigPath = "/etc/rancher/rke2/rke2.yaml"
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return "", fmt.Errorf("failed to build kubeconfig: %w", err)
		}
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return "", fmt.Errorf("failed to initialize discovery client: %w", err)
	}

	versionInfo, err := discoveryClient.ServerVersion()
	if err != nil {
		return "", fmt.Errorf("failed to fetch cluster version: %w", err)
	}

	version := strings.TrimSpace(versionInfo.GitVersion)
	if version == "" {
		return "", fmt.Errorf("kube api response did not include gitVersion")
	}

	return version, nil
}
