package kube

import (
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

type HelmChartConfigObject struct {
	Name      string
	Namespace string
	Content   string
}

type helmChartConfigItem struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   helmObjectMeta `json:"metadata"`
	Spec       map[string]any `json:"spec"`
}

type helmObjectMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

func kubeDynamicClient() (dynamic.Interface, error) {
	api, err := kubeAPIClient()
	if err != nil {
		return nil, err
	}

	restConfig := &rest.Config{Host: api.BaseURL}
	authHeader := strings.TrimSpace(api.AuthHeader)
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		restConfig.BearerToken = strings.TrimSpace(authHeader[len("Bearer "):])
	}

	dynamicClient, err := dynamic.NewForConfigAndClient(restConfig, api.Client)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize kubernetes dynamic client: %w", err)
	}

	return dynamicClient, nil
}

// ListHelmChartConfigsByIdentity lists HelmChartConfig objects in the cluster that match the given name and namespace.
func ListHelmChartConfigsByIdentity(name string, namespace string) ([]HelmChartConfigObject, error) {
	trimmedName := strings.TrimSpace(name)
	trimmedNamespace := strings.TrimSpace(namespace)
	if trimmedName == "" {
		return nil, fmt.Errorf("helmchartconfig name cannot be empty")
	}
	if trimmedNamespace == "" {
		return nil, fmt.Errorf("helmchartconfig namespace cannot be empty")
	}

	dynamicClient, err := kubeDynamicClient()
	if err != nil {
		return nil, err
	}

	gvr := schema.GroupVersionResource{Group: "helm.cattle.io", Version: "v1", Resource: "helmchartconfigs"}
	list, err := dynamicClient.Resource(gvr).Namespace(trimmedNamespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list helmchartconfigs in %s: %w", trimmedNamespace, err)
	}

	results := make([]HelmChartConfigObject, 0, len(list.Items))
	for _, item := range list.Items {
		if strings.TrimSpace(item.GetName()) != trimmedName {
			continue
		}
		if strings.TrimSpace(item.GetNamespace()) != trimmedNamespace {
			continue
		}

		spec, _, err := unstructured.NestedMap(item.Object, "spec")
		if err != nil {
			return nil, err
		}

		manifest := helmChartConfigItem{
			APIVersion: item.GetAPIVersion(),
			Kind:       item.GetKind(),
			Metadata: helmObjectMeta{
				Name:      item.GetName(),
				Namespace: item.GetNamespace(),
			},
			Spec: spec,
		}
		if strings.TrimSpace(manifest.APIVersion) == "" {
			manifest.APIVersion = "helm.cattle.io/v1"
		}
		if strings.TrimSpace(manifest.Kind) == "" {
			manifest.Kind = "HelmChartConfig"
		}

		contentBytes, err := yaml.Marshal(manifest)
		if err != nil {
			return nil, err
		}

		results = append(results, HelmChartConfigObject{
			Name:      item.GetName(),
			Namespace: item.GetNamespace(),
			Content:   string(contentBytes),
		})
	}

	return results, nil
}
