package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	rke2NodeArgsAnnotationKey   = "rke2.io/node-args"
	rke2HostnameAnnotationKey   = "rke2.io/hostname"
	rke2InternalIPAnnotationKey = "rke2.io/internal-ip"
	serviceAccountNamespace     = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

func DiscoverRKE2DataDirFromLocalNodeArgs() (string, error) {
	clientset, err := kubeClientset()
	if err != nil {
		return "", err
	}

	nodeNames := discoverLocalNodeNameCandidates(clientset)
	if len(nodeNames) == 0 {
		return "", nil
	}

	var failures []string
	for _, nodeName := range nodeNames {
		dataDir, found, findErr := dataDirFromNodeArgsAnnotation(clientset, nodeName)
		if findErr != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", nodeName, findErr))
			continue
		}
		if found {
			return dataDir, nil
		}
	}

	fallbackDataDir, fallbackFound, fallbackErr := dataDirFromNodeAnnotationsByHostIdentity(clientset)
	if fallbackErr != nil {
		failures = append(failures, fmt.Sprintf("annotation-identity-fallback: %v", fallbackErr))
	} else if fallbackFound {
		return fallbackDataDir, nil
	}

	if len(failures) > 0 {
		return "", fmt.Errorf("unable to read data-dir from node annotation (%s)", strings.Join(failures, "; "))
	}

	return "", nil
}

func discoverLocalNodeNameCandidates(clientset kubernetes.Interface) []string {
	unique := map[string]struct{}{}
	result := []string{}

	add := func(value string) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return
		}
		if _, found := unique[trimmed]; found {
			return
		}
		unique[trimmed] = struct{}{}
		result = append(result, trimmed)
	}

	add(os.Getenv("NODE_NAME"))
	add(os.Getenv("RKE2_NODE_NAME"))
	add(os.Getenv("KUBERNETES_NODE_NAME"))

	hostname, _ := os.Hostname()
	for _, candidate := range hostnameCandidates(hostname) {
		add(candidate)
	}

	namespaceBytes, err := os.ReadFile(serviceAccountNamespace)
	if err == nil {
		namespace := strings.TrimSpace(string(namespaceBytes))
		if namespace != "" && strings.TrimSpace(hostname) != "" {
			nodeName, nodeErr := nodeNameForPod(clientset, namespace, hostname)
			if nodeErr == nil {
				add(nodeName)
			}
		}
	}

	return result
}

func hostnameCandidates(hostname string) []string {
	trimmed := strings.TrimSpace(hostname)
	if trimmed == "" {
		return nil
	}

	result := []string{trimmed}
	if idx := strings.Index(trimmed, "."); idx > 0 {
		short := strings.TrimSpace(trimmed[:idx])
		if short != "" && short != trimmed {
			result = append(result, short)
		}
	}

	return result
}

func nodeNameForPod(clientset kubernetes.Interface, namespace string, podName string) (string, error) {
	pod, err := clientset.CoreV1().Pods(namespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to get pod %s/%s: %w", namespace, podName, err)
	}

	return strings.TrimSpace(pod.Spec.NodeName), nil
}

func dataDirFromNodeArgsAnnotation(clientset kubernetes.Interface, nodeName string) (string, bool, error) {
	trimmedNodeName := strings.TrimSpace(nodeName)
	if trimmedNodeName == "" {
		return "", false, nil
	}

	node, err := clientset.CoreV1().Nodes().Get(context.Background(), trimmedNodeName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to get node %s: %w", trimmedNodeName, err)
	}

	rawArgs := ""
	if node.Annotations != nil {
		rawArgs = strings.TrimSpace(node.Annotations[rke2NodeArgsAnnotationKey])
	}

	return parseDataDirFromNodeArgs(rawArgs)
}

func dataDirFromNodeAnnotationsByHostIdentity(clientset kubernetes.Interface) (string, bool, error) {
	hostname, _ := os.Hostname()
	localHostnameCandidates := hostnameCandidates(hostname)
	localIPs := localIPSet()
	continueToken := ""
	dataDirs := map[string]struct{}{}

	for {
		nodes, err := listNodesPage(clientset, continueToken)
		if err != nil {
			return "", false, err
		}

		for _, node := range nodes.Items {
			if !annotationMatchesLocalIdentity(node.Annotations, localHostnameCandidates, localIPs) {
				continue
			}

			rawArgs := ""
			if node.Annotations != nil {
				rawArgs = strings.TrimSpace(node.Annotations[rke2NodeArgsAnnotationKey])
			}

			dataDir, found, err := parseDataDirFromNodeArgs(rawArgs)
			if err != nil {
				return "", false, fmt.Errorf("node %q: %w", strings.TrimSpace(node.Name), err)
			}
			if !found {
				continue
			}

			dataDirs[dataDir] = struct{}{}
		}

		if strings.TrimSpace(nodes.Continue) == "" {
			break
		}
		continueToken = strings.TrimSpace(nodes.Continue)
	}

	if len(dataDirs) == 0 {
		return "", false, nil
	}

	if len(dataDirs) > 1 {
		values := make([]string, 0, len(dataDirs))
		for value := range dataDirs {
			values = append(values, value)
		}
		return "", false, fmt.Errorf("found multiple data-dir values for local-node annotation matches: %s", strings.Join(values, ", "))
	}

	for value := range dataDirs {
		return value, true, nil
	}

	return "", false, nil
}

func listNodesPage(clientset kubernetes.Interface, continueToken string) (*corev1.NodeList, error) {
	list, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{
		Limit:    500,
		Continue: strings.TrimSpace(continueToken),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	return list, nil
}

func localIPSet() map[string]struct{} {
	result := map[string]struct{}{}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return result
	}

	for _, address := range addresses {
		switch typed := address.(type) {
		case *net.IPNet:
			if typed.IP != nil {
				result[typed.IP.String()] = struct{}{}
			}
		case *net.IPAddr:
			if typed.IP != nil {
				result[typed.IP.String()] = struct{}{}
			}
		}
	}

	return result
}

func annotationMatchesLocalIdentity(annotations map[string]string, localHostnameCandidates []string, localIPs map[string]struct{}) bool {
	if len(annotations) == 0 {
		return false
	}

	annotationHostname := strings.TrimSpace(annotations[rke2HostnameAnnotationKey])
	if annotationHostname != "" {
		for _, candidate := range localHostnameCandidates {
			if strings.EqualFold(annotationHostname, strings.TrimSpace(candidate)) {
				return true
			}
		}
	}

	annotationIPs := strings.TrimSpace(annotations[rke2InternalIPAnnotationKey])
	if annotationIPs == "" {
		return false
	}

	for _, value := range strings.Split(annotationIPs, ",") {
		ip := strings.TrimSpace(value)
		if ip == "" {
			continue
		}
		if _, found := localIPs[ip]; found {
			return true
		}
	}

	return false
}

func parseDataDirFromNodeArgs(raw string) (string, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false, nil
	}

	args := []string{}
	if err := json.Unmarshal([]byte(trimmed), &args); err != nil {
		return "", false, fmt.Errorf("invalid %s annotation JSON: %w", rke2NodeArgsAnnotationKey, err)
	}

	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])

		switch {
		case arg == "--data-dir" || arg == "-d":
			if i+1 >= len(args) {
				return "", false, fmt.Errorf("%s annotation has %s without value", rke2NodeArgsAnnotationKey, arg)
			}
			value := strings.TrimSpace(args[i+1])
			if value == "" {
				return "", false, fmt.Errorf("%s annotation has empty %s value", rke2NodeArgsAnnotationKey, arg)
			}
			return value, true, nil
		case strings.HasPrefix(arg, "--data-dir="):
			value := strings.TrimSpace(strings.TrimPrefix(arg, "--data-dir="))
			if value == "" {
				return "", false, fmt.Errorf("%s annotation has empty --data-dir value", rke2NodeArgsAnnotationKey)
			}
			return value, true, nil
		case strings.HasPrefix(arg, "-d="):
			value := strings.TrimSpace(strings.TrimPrefix(arg, "-d="))
			if value == "" {
				return "", false, fmt.Errorf("%s annotation has empty -d value", rke2NodeArgsAnnotationKey)
			}
			return value, true, nil
		}
	}

	return "", false, nil
}
