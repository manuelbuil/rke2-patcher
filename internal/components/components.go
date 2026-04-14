package components

import (
	"fmt"
	"sort"
	"strings"
)

type Component struct {
	Key                 string
	Repository          string
	HelmChartConfigName string
	Workload            WorkloadRef
}

type WorkloadRef struct {
	Kind      string
	Namespace string
	Name      string
}

var registry = map[string]Component{
	"rke2-traefik": {
		Repository:          "rancher/hardened-traefik",
		HelmChartConfigName: "rke2-traefik",
		Workload: WorkloadRef{
			Kind:      "daemonset",
			Namespace: "kube-system",
			Name:      "rke2-traefik",
		},
	},
	"rke2-ingress-nginx": {
		Repository:          "rancher/nginx-ingress-controller",
		HelmChartConfigName: "rke2-ingress-nginx",
		Workload: WorkloadRef{
			Kind:      "daemonset",
			Namespace: "kube-system",
			Name:      "rke2-ingress-nginx-controller",
		},
	},
	"rke2-coredns": {
		Repository:          "rancher/hardened-coredns",
		HelmChartConfigName: "rke2-coredns",
		Workload: WorkloadRef{
			Kind:      "deployment",
			Namespace: "kube-system",
			Name:      "rke2-coredns-rke2-coredns",
		},
	},
	"rke2-dns-node-cache": {
		Repository:          "rancher/hardened-dns-node-cache",
		HelmChartConfigName: "rke2-coredns",
		Workload: WorkloadRef{
			Kind:      "daemonset",
			Namespace: "kube-system",
			Name:      "node-local-dns",
		},
	},
	"rke2-calico-operator": {
		Repository:          "rancher/mirrored-calico-operator",
		HelmChartConfigName: "rke2-calico",
		Workload: WorkloadRef{
			Kind:      "deployment",
			Namespace: "tigera-operator",
			Name:      "tigera-operator",
		},
	},
	"rke2-cilium-operator": {
		Repository:          "rancher/mirrored-cilium-operator-generic",
		HelmChartConfigName: "rke2-cilium",
		Workload: WorkloadRef{
			Kind:      "deployment",
			Namespace: "kube-system",
			Name:      "cilium-operator",
		},
	},
	"rke2-metrics-server": {
		Repository:          "rancher/hardened-k8s-metrics-server",
		HelmChartConfigName: "rke2-metrics-server",
		Workload: WorkloadRef{
			Kind:      "deployment",
			Namespace: "kube-system",
			Name:      "rke2-metrics-server",
		},
	},
	"rke2-flannel": {
		Repository:          "rancher/hardened-flannel",
		HelmChartConfigName: "rke2-flannel",
		Workload: WorkloadRef{
			Kind:      "daemonset",
			Namespace: "kube-system",
			Name:      "kube-flannel-ds",
		},
	},
	"rke2-canal-calico": {
		Repository:          "rancher/hardened-calico",
		HelmChartConfigName: "rke2-canal",
		Workload: WorkloadRef{
			Kind:      "daemonset",
			Namespace: "kube-system",
			Name:      "rke2-canal",
		},
	},
	"rke2-canal-flannel": {
		Repository:          "rancher/hardened-flannel",
		HelmChartConfigName: "rke2-canal",
		Workload: WorkloadRef{
			Kind:      "daemonset",
			Namespace: "kube-system",
			Name:      "rke2-canal",
		},
	},
	"rke2-coredns-cluster-autoscaler": {
		Repository:          "rancher/hardened-cluster-autoscaler",
		HelmChartConfigName: "rke2-cluster-autoscaler",
		Workload: WorkloadRef{
			Kind:      "deployment",
			Namespace: "kube-system",
			Name:      "rke2-coredns-rke2-coredns-autoscaler",
		},
	},
	"rke2-snapshot-controller": {
		Repository:          "rancher/hardened-snapshot-controller",
		HelmChartConfigName: "rke2-snapshot-controller",
		Workload: WorkloadRef{
			Kind:      "deployment",
			Namespace: "kube-system",
			Name:      "rke2-snapshot-controller",
		},
	},
}

// Resolves the component struct of the chosen component
func Resolve(name string) (Component, error) {
	key, found := canonicalKey(name)
	component, found := registry[key]
	if !found {
		return Component{}, fmt.Errorf("unsupported component %q", name)
	}

	component.Key = key

	return component, nil
}

func Supported() []string {
	items := make([]string, 0, len(registry))
	for name := range registry {
		items = append(items, name)
	}
	sort.Strings(items)

	return items
}

func CLIName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}

	if key, found := canonicalKey(trimmed); found {
		return key
	}

	return trimmed
}

func SameComponent(a string, b string) bool {
	return strings.EqualFold(CLIName(a), CLIName(b))
}

func canonicalKey(name string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return "", false
	}

	if _, found := registry[key]; found {
		return key, true
	}

	return key, false
}
