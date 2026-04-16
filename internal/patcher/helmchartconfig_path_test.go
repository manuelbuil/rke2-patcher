package patcher

import (
	"path/filepath"
	"testing"
)

func TestBuildHelmChartConfig_UsesDataDirEnv(t *testing.T) {
	t.Setenv("RKE2_PATCHER_DATA_DIR", "/tmp/from-data-env")

	filePath, _, _ := BuildHelmChartConfig("rke2-traefik", "rke2-traefik", "rancher/hardened-traefik", "v3.4.0")

	expectedPath := filepath.Join("/tmp/from-data-env", "server", "manifests", "rke2-traefik-config-rke2-patcher.yaml")
	if filePath != expectedPath {
		t.Fatalf("expected path %q, got %q", expectedPath, filePath)
	}
}

func TestBuildHelmChartConfig_UsesChartNameForSharedChartFile(t *testing.T) {
	t.Setenv("RKE2_PATCHER_DATA_DIR", "/tmp/from-data-env")

	calicoPath, _, _ := BuildHelmChartConfig("rke2-canal-calico", "rke2-canal", "rancher/hardened-calico", "v3.31.4-build20260408")
	flannelPath, _, _ := BuildHelmChartConfig("rke2-canal-flannel", "rke2-canal", "rancher/hardened-flannel", "v0.28.2-build20260414")

	expectedPath := filepath.Join("/tmp/from-data-env", "server", "manifests", "rke2-canal-config-rke2-patcher.yaml")
	if calicoPath != expectedPath {
		t.Fatalf("expected calico path %q, got %q", expectedPath, calicoPath)
	}
	if flannelPath != expectedPath {
		t.Fatalf("expected flannel path %q, got %q", expectedPath, flannelPath)
	}
}
