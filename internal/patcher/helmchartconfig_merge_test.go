package patcher

import (
	"strings"
	"testing"
)

func TestMergeHelmChartConfigWithContents(t *testing.T) {
	existingContent := `apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-traefik
  namespace: kube-system
spec:
  valuesContent: |-
    service:
      type: ClusterIP
`

	generatedContent := `apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-traefik
  namespace: kube-system
spec:
  valuesContent: |-
    image:
      repository: rancher/hardened-traefik
      tag: new-tag
`

	merged, err := MergeHelmChartConfigWithContents(generatedContent, []string{existingContent})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(merged, "type: ClusterIP") {
		t.Fatalf("expected merged content to include existing values content: %s", merged)
	}
	if !strings.Contains(merged, "repository: rancher/hardened-traefik") || !strings.Contains(merged, "tag: new-tag") {
		t.Fatalf("expected merged content to include generated image values: %s", merged)
	}
}

func TestHelmChartConfigIdentityFromContent(t *testing.T) {
	content := `apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-traefik
  namespace: kube-system
spec:
  valuesContent: |-
    image:
      repository: rancher/hardened-traefik
      tag: v3.4.0
`

	name, namespace, err := HelmChartConfigIdentityFromContent(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if name != "rke2-traefik" || namespace != "kube-system" {
		t.Fatalf("unexpected identity: %s/%s", namespace, name)
	}
}
