package components

import (
	"fmt"
	"sort"
	"strings"
)

type Component struct {
	Name                string
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
	"traefik": {
		Name:                "rke2-traefik",
		Repository:          "rancher/hardened-traefik",
		HelmChartConfigName: "rke2-traefik",
		Workload: WorkloadRef{
			Kind:      "daemonset",
			Namespace: "kube-system",
			Name:      "rke2-traefik",
		},
	},
	"ingress-nginx": {
		Name:                "rke2-ingress-nginx-controller",
		Repository:          "rancher/nginx-ingress-controller",
		HelmChartConfigName: "rke2-ingress-nginx",
		Workload: WorkloadRef{
			Kind:      "daemonset",
			Namespace: "kube-system",
			Name:      "rke2-ingress-nginx-controller",
		},
	},
	"coredns": {
		Name:                "coredns",
		Repository:          "rancher/hardened-coredns",
		HelmChartConfigName: "rke2-coredns",
		Workload: WorkloadRef{
			Kind:      "deployment",
			Namespace: "kube-system",
			Name:      "rke2-coredns-rke2-coredns",
		},
	},
	"dns-node-cache": {
		Name:                "dns-node-cache",
		Repository:          "rancher/hardened-dns-node-cache",
		HelmChartConfigName: "rke2-coredns",
		Workload: WorkloadRef{
			Kind:      "daemonset",
			Namespace: "kube-system",
			Name:      "node-local-dns",
		},
	},
	"calico-operator": {
		Name:                "calico-operator",
		Repository:          "rancher/mirrored-calico-operator",
		HelmChartConfigName: "rke2-calico",
		Workload: WorkloadRef{
			Kind:      "deployment",
			Namespace: "tigera-operator",
			Name:      "tigera-operator",
		},
	},
	"cilium-operator": {
		Name:                "cilium-operator",
		Repository:          "rancher/mirrored-cilium-operator-generic",
		HelmChartConfigName: "rke2-cilium",
		Workload: WorkloadRef{
			Kind:      "deployment",
			Namespace: "kube-system",
			Name:      "cilium-operator",
		},
	},
	"metrics-server": {
		Name:                "metrics-server",
		Repository:          "rancher/hardened-k8s-metrics-server",
		HelmChartConfigName: "rke2-metrics-server",
		Workload: WorkloadRef{
			Kind:      "deployment",
			Namespace: "kube-system",
			Name:      "rke2-metrics-server",
		},
	},
	"flannel": {
		Name:                "flannel",
		Repository:          "rancher/hardened-flannel",
		HelmChartConfigName: "rke2-flannel",
		Workload: WorkloadRef{
			Kind:      "daemonset",
			Namespace: "kube-system",
			Name:      "kube-flannel-ds",
		},
	},
	"canal-calico": {
		Name:                "canal-calico",
		Repository:          "rancher/hardened-calico",
		HelmChartConfigName: "rke2-canal",
		Workload: WorkloadRef{
			Kind:      "daemonset",
			Namespace: "kube-system",
			Name:      "rke2-canal",
		},
	},
	"canal-flannel": {
		Name:                "canal-flannel",
		Repository:          "rancher/hardened-flannel",
		HelmChartConfigName: "rke2-canal",
		Workload: WorkloadRef{
			Kind:      "daemonset",
			Namespace: "kube-system",
			Name:      "rke2-canal",
		},
	},
	"coredns-cluster-autoscaler": {
		Name:                "coredns-cluster-autoscaler",
		Repository:          "rancher/hardened-cluster-autoscaler",
		HelmChartConfigName: "rke2-cluster-autoscaler",
		Workload: WorkloadRef{
			Kind:      "deployment",
			Namespace: "kube-system",
			Name:      "rke2-coredns-rke2-coredns-autoscaler",
		},
	},
	"snapshot-controller": {
		Name:                "snapshot-controller",
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
	key := strings.ToLower(strings.TrimSpace(name))
	key = strings.TrimPrefix(key, "rke2-")
	component, found := registry[key]
	if !found {
		return Component{}, fmt.Errorf("unsupported component %q", name)
	}

	return component, nil
}

func Supported() []string {
	items := make([]string, 0, len(registry))
	for name := range registry {
		items = append(items, "rke2-"+name)
	}
	sort.Strings(items)

	return items
}

func CLIName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}

	if strings.HasPrefix(strings.ToLower(trimmed), "rke2-") {
		return strings.ToLower(trimmed)
	}

	key := strings.ToLower(trimmed)
	if _, found := registry[key]; found {
		return "rke2-" + key
	}

	for registryKey, component := range registry {
		if strings.EqualFold(strings.TrimSpace(component.Name), trimmed) {
			return "rke2-" + registryKey
		}
	}

	return trimmed
}
