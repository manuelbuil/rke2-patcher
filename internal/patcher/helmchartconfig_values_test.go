package patcher

import (
	"strings"
	"testing"
)

func TestRenderValuesContent_CalicoOperatorRegistryFromEnv(t *testing.T) {
	tests := []struct {
		name             string
		registryEnvValue string
		imageName        string
		expectedRegistry string
		expectedImage    string
	}{
		{
			name:             "default registry when unset",
			registryEnvValue: "",
			imageName:        "docker.io/rancher/mirrored-calico-operator",
			expectedRegistry: "registry.rancher.com",
			expectedImage:    "rancher/mirrored-calico-operator",
		},
		{
			name:             "custom registry host with scheme",
			registryEnvValue: "https://registry-1.docker.io",
			imageName:        "registry-1.docker.io/rancher/mirrored-calico-operator",
			expectedRegistry: "registry-1.docker.io",
			expectedImage:    "rancher/mirrored-calico-operator",
		},
		{
			name:             "image without registry prefix remains unchanged",
			registryEnvValue: "registry.example.local:5000",
			imageName:        "rancher/mirrored-calico-operator",
			expectedRegistry: "registry.example.local:5000",
			expectedImage:    "rancher/mirrored-calico-operator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(registryEnv, tt.registryEnvValue)

			values := renderValuesContent("calico-operator", "rke2-calico", tt.imageName, "v3.31.0")

			expectedRegistryLine := "registry: " + tt.expectedRegistry
			if !strings.Contains(values, expectedRegistryLine) {
				t.Fatalf("expected valuesContent to contain %q, got:\n%s", expectedRegistryLine, values)
			}

			expectedImageLine := "image: " + tt.expectedImage
			if !strings.Contains(values, expectedImageLine) {
				t.Fatalf("expected valuesContent to contain %q, got:\n%s", expectedImageLine, values)
			}
		})
	}
}
