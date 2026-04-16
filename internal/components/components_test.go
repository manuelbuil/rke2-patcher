package components

import "testing"

func TestResolve_CoreDNSClusterAutoscalerUsesCoreDNSChartConfig(t *testing.T) {
	component, err := Resolve("rke2-coredns-cluster-autoscaler")
	if err != nil {
		t.Fatalf("expected component to resolve: %v", err)
	}

	if component.HelmChartConfigName != "rke2-coredns" {
		t.Fatalf("expected HelmChartConfigName rke2-coredns, got %q", component.HelmChartConfigName)
	}
}
