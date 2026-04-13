package kube

import (
	"fmt"
	"net/http"
	"strings"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func ClusterVersion() (string, error) {
	api, err := kubeAPIClient()
	if err != nil {
		return "", err
	}

	return clusterVersion(api)
}

func clusterVersion(api kubeAPI) (string, error) {
	restConfig := &rest.Config{Host: api.BaseURL}

	httpClient := api.Client
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	authHeader := strings.TrimSpace(api.AuthHeader)
	if authHeader != "" {
		wrapped := *httpClient
		baseTransport := wrapped.Transport
		if baseTransport == nil {
			baseTransport = http.DefaultTransport
		}
		wrapped.Transport = roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			cloned := request.Clone(request.Context())
			cloned.Header = request.Header.Clone()
			cloned.Header.Set("Authorization", authHeader)
			return baseTransport.RoundTrip(cloned)
		})
		httpClient = &wrapped
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfigAndClient(restConfig, httpClient)
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
