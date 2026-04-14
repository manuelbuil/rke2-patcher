package patcher

import (
	"strings"
	"testing"
)

const patcherComment = "# change made by rke2-patcher"

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

func TestRenderValuesContent_AddsPatcherCommentToImageAndRepositoryLines(t *testing.T) {
	valuesForCalico := renderValuesContent("calico-operator", "rke2-calico", "docker.io/rancher/mirrored-calico-operator", "v3.31.0")
	if !strings.Contains(valuesForCalico, "image: rancher/mirrored-calico-operator # change made by rke2-patcher") {
		t.Fatalf("expected calico image line to include patcher comment, got:\n%s", valuesForCalico)
	}

	valuesForIngress := renderValuesContent("ingress-nginx", "rke2-ingress-nginx", "rancher/hardened-ingress-nginx", "v1.0.0")
	if !strings.Contains(valuesForIngress, "repository: rancher/hardened-ingress-nginx # change made by rke2-patcher") {
		t.Fatalf("expected ingress repository line to include patcher comment, got:\n%s", valuesForIngress)
	}
	if !strings.Contains(valuesForIngress, "tag: v1.0.0 # change made by rke2-patcher") {
		t.Fatalf("expected ingress tag line to include patcher comment, got:\n%s", valuesForIngress)
	}
}

func TestRenderValuesContent_AllGeneratedLinesHavePatcherComment(t *testing.T) {
	tests := []struct {
		name          string
		componentName string
		chartName     string
		imageName     string
		imageTag      string
	}{
		{name: "default", componentName: "rke2-traefik", chartName: "rke2-traefik", imageName: "rancher/hardened-traefik", imageTag: "v3.6.9"},
		{name: "ingress nginx", componentName: "ingress-nginx", chartName: "rke2-ingress-nginx", imageName: "rancher/hardened-ingress-nginx", imageTag: "v1.0.0"},
		{name: "calico operator", componentName: "calico-operator", chartName: "rke2-calico", imageName: "docker.io/rancher/mirrored-calico-operator", imageTag: "v3.31.0"},
		{name: "cilium operator", componentName: "cilium-operator", chartName: "rke2-cilium", imageName: "rancher/mirrored-cilium-operator-generic", imageTag: "v1.17.5"},
		{name: "canal calico", componentName: "canal-calico", chartName: "rke2-canal", imageName: "rancher/hardened-calico", imageTag: "v1.0.0"},
		{name: "canal flannel", componentName: "canal-flannel", chartName: "rke2-canal", imageName: "rancher/hardened-flannel", imageTag: "v1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := renderValuesContent(tt.componentName, tt.chartName, tt.imageName, tt.imageTag)
			for _, line := range strings.Split(values, "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					continue
				}
				if !strings.Contains(line, patcherComment) {
					t.Fatalf("expected every generated line to include patcher comment, missing on line %q\nfull values:\n%s", line, values)
				}
			}
		})
	}
}

func TestBuildHelmChartConfigWithDataDir_GeneratedContentParsesForPatchedComponents(t *testing.T) {
	tests := []struct {
		name          string
		componentName string
		chartName     string
		imageName     string
		imageTag      string
	}{
		{name: "default", componentName: "rke2-traefik", chartName: "rke2-traefik", imageName: "rancher/hardened-traefik", imageTag: "v3.6.9"},
		{name: "ingress nginx", componentName: "ingress-nginx", chartName: "rke2-ingress-nginx", imageName: "rancher/hardened-ingress-nginx", imageTag: "v1.0.0"},
		{name: "calico operator", componentName: "calico-operator", chartName: "rke2-calico", imageName: "docker.io/rancher/mirrored-calico-operator", imageTag: "v3.31.0"},
		{name: "canal calico", componentName: "canal-calico", chartName: "rke2-canal", imageName: "rancher/hardened-calico", imageTag: "v1.0.0"},
		{name: "canal flannel", componentName: "canal-flannel", chartName: "rke2-canal", imageName: "rancher/hardened-flannel", imageTag: "v1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, content := BuildHelmChartConfigWithDataDir(tt.componentName, tt.chartName, tt.imageName, tt.imageTag, "/tmp")

			valuesContent, err := ExtractValuesContent(content)
			if err != nil {
				t.Fatalf("expected generated HelmChartConfig to parse, got error: %v\ncontent:\n%s", err, content)
			}

			if strings.TrimSpace(valuesContent) == "" {
				t.Fatalf("expected non-empty valuesContent, got empty content:\n%s", content)
			}
		})
	}
}

func TestRenderValuesContent_CanalCalicoPatchesFourCalicoImageKeys(t *testing.T) {
	values := renderValuesContent("canal-calico", "rke2-canal", "rancher/hardened-calico", "v3.31.4")

	if !strings.Contains(values, "cniImage:") || !strings.Contains(values, "nodeImage:") || !strings.Contains(values, "flexvolImage:") || !strings.Contains(values, "kubeControllerImage:") {
		t.Fatalf("expected canal-calico values to patch cni/node/flexvol/kubeController images, got:\n%s", values)
	}
}
