package kube

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	rke2NodeArgsAnnotationKey   = "rke2.io/node-args"
	rke2HostnameAnnotationKey   = "rke2.io/hostname"
	rke2InternalIPAnnotationKey = "rke2.io/internal-ip"
	serviceAccountNamespace     = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

type podNodeNameResponse struct {
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
}

type nodeAnnotationsResponse struct {
	Metadata struct {
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
}

type nodeListResponse struct {
	Continue string `json:"continue"`
	Items    []struct {
		Metadata struct {
			Name        string            `json:"name"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	} `json:"items"`
}

func DiscoverRKE2DataDirFromLocalNodeArgs() (string, error) {
	api, err := kubeAPIClient()
	if err != nil {
		return "", err
	}

	nodeNames := discoverLocalNodeNameCandidates(api)
	if len(nodeNames) == 0 {
		return "", nil
	}

	var failures []string
	for _, nodeName := range nodeNames {
		dataDir, found, findErr := dataDirFromNodeArgsAnnotation(api, nodeName)
		if findErr != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", nodeName, findErr))
			continue
		}
		if found {
			return dataDir, nil
		}
	}

	fallbackDataDir, fallbackFound, fallbackErr := dataDirFromNodeAnnotationsByHostIdentity(api)
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

func discoverLocalNodeNameCandidates(api kubeAPI) []string {
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
			nodeName, nodeErr := nodeNameForPod(api, namespace, hostname)
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

func nodeNameForPod(api kubeAPI, namespace string, podName string) (string, error) {
	requestURL := fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s", api.BaseURL, url.PathEscape(namespace), url.PathEscape(podName))

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(api.AuthHeader) != "" {
		req.Header.Set("Authorization", api.AuthHeader)
	}

	resp, err := api.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("failed to get pod %s/%s: status %d: %s", namespace, podName, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var pod podNodeNameResponse
	if err := json.NewDecoder(resp.Body).Decode(&pod); err != nil {
		return "", err
	}

	return strings.TrimSpace(pod.Spec.NodeName), nil
}

func dataDirFromNodeArgsAnnotation(api kubeAPI, nodeName string) (string, bool, error) {
	trimmedNodeName := strings.TrimSpace(nodeName)
	if trimmedNodeName == "" {
		return "", false, nil
	}

	requestURL := fmt.Sprintf("%s/api/v1/nodes/%s", api.BaseURL, url.PathEscape(trimmedNodeName))

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return "", false, err
	}
	if strings.TrimSpace(api.AuthHeader) != "" {
		req.Header.Set("Authorization", api.AuthHeader)
	}

	resp, err := api.Client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", false, fmt.Errorf("failed to get node %s: status %d: %s", trimmedNodeName, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var node nodeAnnotationsResponse
	if err := json.NewDecoder(resp.Body).Decode(&node); err != nil {
		return "", false, err
	}

	rawArgs := ""
	if node.Metadata.Annotations != nil {
		rawArgs = strings.TrimSpace(node.Metadata.Annotations[rke2NodeArgsAnnotationKey])
	}

	return parseDataDirFromNodeArgs(rawArgs)
}

func dataDirFromNodeAnnotationsByHostIdentity(api kubeAPI) (string, bool, error) {
	hostname, _ := os.Hostname()
	localHostnameCandidates := hostnameCandidates(hostname)
	localIPs := localIPSet()
	continueToken := ""
	dataDirs := map[string]struct{}{}

	for {
		nodes, err := listNodesPage(api, continueToken)
		if err != nil {
			return "", false, err
		}

		for _, node := range nodes.Items {
			if !annotationMatchesLocalIdentity(node.Metadata.Annotations, localHostnameCandidates, localIPs) {
				continue
			}

			rawArgs := ""
			if node.Metadata.Annotations != nil {
				rawArgs = strings.TrimSpace(node.Metadata.Annotations[rke2NodeArgsAnnotationKey])
			}

			dataDir, found, err := parseDataDirFromNodeArgs(rawArgs)
			if err != nil {
				return "", false, fmt.Errorf("node %q: %w", strings.TrimSpace(node.Metadata.Name), err)
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

func listNodesPage(api kubeAPI, continueToken string) (nodeListResponse, error) {
	requestURL := api.BaseURL + "/api/v1/nodes?limit=500"
	if strings.TrimSpace(continueToken) != "" {
		requestURL += "&continue=" + url.QueryEscape(continueToken)
	}

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nodeListResponse{}, err
	}
	if strings.TrimSpace(api.AuthHeader) != "" {
		req.Header.Set("Authorization", api.AuthHeader)
	}

	resp, err := api.Client.Do(req)
	if err != nil {
		return nodeListResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nodeListResponse{}, fmt.Errorf("failed to list nodes: status %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var list nodeListResponse
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nodeListResponse{}, err
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
