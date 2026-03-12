package patcher

import (
	"path/filepath"
	"testing"
)

func TestBuildHelmChartConfigWithDataDir_OverrideTakesPrecedence(t *testing.T) {
	t.Setenv("RKE2_PATCHER_MANIFESTS_DIR", "/tmp/from-env")
	t.Setenv("RKE2_PATCHER_DATA_DIR", "/tmp/from-data-env")

	filePath, _ := BuildHelmChartConfigWithDataDir("traefik", "rke2-traefik", "rancher/hardened-traefik", "v3.4.0", "/tmp/from-flag")

	expectedPath := filepath.Join("/tmp/from-flag", "server", "manifests", "traefik-config-rke2-patcher.yaml")
	if filePath != expectedPath {
		t.Fatalf("expected path %q, got %q", expectedPath, filePath)
	}
}

func TestBuildHelmChartConfigWithDataDir_UsesDataDirEnvByDefault(t *testing.T) {
	t.Setenv("RKE2_PATCHER_DATA_DIR", "/tmp/from-data-env")
	t.Setenv("RKE2_PATCHER_MANIFESTS_DIR", "")

	filePath, _ := BuildHelmChartConfigWithDataDir("traefik", "rke2-traefik", "rancher/hardened-traefik", "v3.4.0", "")

	expectedPath := filepath.Join("/tmp/from-data-env", "server", "manifests", "traefik-config-rke2-patcher.yaml")
	if filePath != expectedPath {
		t.Fatalf("expected path %q, got %q", expectedPath, filePath)
	}
}
