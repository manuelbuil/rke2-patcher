package kube

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/components"
)

type PodImageSummary struct {
	Image string
	Count int
}

type podList struct {
	Continue string `json:"continue"`
	Items    []struct {
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
		Spec struct {
			InitContainers []struct {
				Image string `json:"image"`
			} `json:"initContainers"`
			Containers []struct {
				Image string `json:"image"`
			} `json:"containers"`
		} `json:"spec"`
	} `json:"items"`
}

type workloadGetResponse struct {
	Spec struct {
		Selector struct {
			MatchLabels map[string]string `json:"matchLabels"`
		} `json:"selector"`
	} `json:"spec"`
}

func ListRunningImages(workload components.WorkloadRef, componentRepository string) ([]PodImageSummary, error) {
	api, err := kubeAPIClient()
	if err != nil {
		return nil, err
	}

	counts := make(map[string]int)

	namespace := workload.Namespace
	kind := workload.Kind
	name := workload.Name
	checked := fmt.Sprintf("%s/%s/%s", kind, namespace, name)

	selector, selectorErr := workloadSelector(api, kind, namespace, name)
	if selectorErr != nil {
		return nil, selectorErr
	}

	continueToken := ""
	for {
		list, listErr := listPodsByNamespaceAndSelectorPage(api, namespace, selector, continueToken)
		if listErr != nil {
			return nil, listErr
		}

		for _, item := range list.Items {
			if item.Status.Phase != "Running" {
				continue
			}

			for _, container := range item.Spec.InitContainers {
				if imageBelongsToRepository(container.Image, componentRepository) {
					counts[container.Image]++
				}
			}

			for _, container := range item.Spec.Containers {
				if imageBelongsToRepository(container.Image, componentRepository) {
					counts[container.Image]++
				}
			}
		}

		if strings.TrimSpace(list.Continue) == "" {
			break
		}
		continueToken = list.Continue
	}

	if len(counts) == 0 {
		return nil, fmt.Errorf("no running image found in configured workload for repository %q (checked: %s)", componentRepository, checked)
	}

	images := make([]PodImageSummary, 0, len(counts))
	for image, count := range counts {
		images = append(images, PodImageSummary{Image: image, Count: count})
	}

	sort.Slice(images, func(i int, j int) bool {
		if images[i].Count == images[j].Count {
			return images[i].Image < images[j].Image
		}

		return images[i].Count > images[j].Count
	})

	return images, nil
}

func listPodsByNamespaceAndSelectorPage(api kubeAPI, namespace string, selector string, continueToken string) (podList, error) {
	requestURL := fmt.Sprintf("%s/api/v1/namespaces/%s/pods?limit=500", api.BaseURL, url.PathEscape(namespace))
	if strings.TrimSpace(selector) != "" {
		requestURL += "&labelSelector=" + url.QueryEscape(selector)
	}
	if strings.TrimSpace(continueToken) != "" {
		requestURL += "&continue=" + url.QueryEscape(continueToken)
	}

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return podList{}, err
	}
	if strings.TrimSpace(api.AuthHeader) != "" {
		req.Header.Set("Authorization", api.AuthHeader)
	}

	resp, err := api.Client.Do(req)
	if err != nil {
		return podList{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return podList{}, fmt.Errorf("kube api returned status %d while listing pods in namespace %q: %s", resp.StatusCode, namespace, strings.TrimSpace(string(bodyBytes)))
	}

	var list podList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return podList{}, err
	}

	return list, nil
}

func workloadSelector(api kubeAPI, kind string, namespace string, name string) (string, error) {
	resource := ""
	switch kind {
	case "daemonset":
		resource = "daemonsets"
	case "deployment":
		resource = "deployments"
	default:
		return "", fmt.Errorf("unsupported workload kind %q", kind)
	}

	requestURL := fmt.Sprintf("%s/apis/apps/v1/namespaces/%s/%s/%s", api.BaseURL, url.PathEscape(namespace), resource, url.PathEscape(name))

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
		return "", fmt.Errorf("workload %s/%s/%s not found", kind, namespace, name)
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("failed to fetch workload %s/%s/%s: status %d: %s", kind, namespace, name, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var workload workloadGetResponse
	if err := json.NewDecoder(resp.Body).Decode(&workload); err != nil {
		return "", err
	}

	if len(workload.Spec.Selector.MatchLabels) == 0 {
		return "", fmt.Errorf("workload %s/%s/%s has empty selector.matchLabels", kind, namespace, name)
	}

	keys := make([]string, 0, len(workload.Spec.Selector.MatchLabels))
	for key := range workload.Spec.Selector.MatchLabels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	selectorParts := make([]string, 0, len(keys))
	for _, key := range keys {
		selectorParts = append(selectorParts, fmt.Sprintf("%s=%s", key, workload.Spec.Selector.MatchLabels[key]))
	}

	return strings.Join(selectorParts, ","), nil
}

func imageBelongsToRepository(image string, componentRepository string) bool {
	imageRepository := imageNameWithoutTagOrDigest(image)
	if imageRepository == componentRepository {
		return true
	}

	return strings.HasSuffix(imageRepository, "/"+componentRepository)
}

// imageNameWithoutTagOrDigest returns the image name without the tag or digest, if present. For example, "rancher/hardened-flannel:v0.1.0" and "rancher/hardened-flannel@sha256:abc123" would both return "rancher/hardened-flannel"
func imageNameWithoutTagOrDigest(image string) string {
	trimmed := strings.TrimSpace(image)
	if idx := strings.Index(trimmed, "@"); idx >= 0 {
		trimmed = trimmed[:idx]
	}

	lastSlash := strings.LastIndex(trimmed, "/")
	lastColon := strings.LastIndex(trimmed, ":")
	if lastColon > lastSlash {
		trimmed = trimmed[:lastColon]
	}

	return trimmed
}

// SplitImage splits an image reference into the image name and the tag or digest.
// For example, "rancher/hardened-flannel:v0.1.0" would return "rancher/hardened-flannel" and
// "v0.1.0", while "rancher/hardened-flannel@sha256:abc123" would return
// "rancher/hardened-flannel" and "sha256:abc123". If no tag or digest is present,
// the second return value defaults to "latest"
func SplitImage(image string) (string, string) {
	trimmed := strings.TrimSpace(image)
	if idx := strings.Index(trimmed, "@"); idx >= 0 {
		return trimmed[:idx], trimmed[idx+1:]
	}

	lastSlash := strings.LastIndex(trimmed, "/")
	lastColon := strings.LastIndex(trimmed, ":")
	if lastColon > lastSlash {
		return trimmed[:lastColon], trimmed[lastColon+1:]
	}

	return trimmed, "latest"
}
