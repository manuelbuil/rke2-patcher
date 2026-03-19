package patcher

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	dataDirEnv  = "RKE2_PATCHER_DATA_DIR"
	registryEnv = "RKE2_PATCHER_REGISTRY"

	helmNamespaceEnv = "RKE2_PATCHER_HELM_NAMESPACE"

	defaultDataDir      = "/var/lib/rancher/rke2"
	defaultNamespace    = "kube-system"
	defaultRegistryHost = "registry.rancher.com"
)

func WriteHelmChartConfig(componentName string, defaultChartConfigName string, imageName string, imageTag string) (string, error) {
	filePath, content := BuildHelmChartConfig(componentName, defaultChartConfigName, imageName, imageTag)

	if err := WriteHelmChartConfigContent(filePath, content); err != nil {
		return filePath, err
	}

	return filePath, nil
}

func WriteHelmChartConfigContent(filePath string, content string) error {
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return err
	}

	return nil
}

func BuildHelmChartConfig(componentName string, defaultChartConfigName string, imageName string, imageTag string) (string, string) {
	return BuildHelmChartConfigWithDataDir(componentName, defaultChartConfigName, imageName, imageTag, "")
}

func BuildHelmChartConfigWithDataDir(componentName string, defaultChartConfigName string, imageName string, imageTag string, dataDirOverride string) (string, string) {
	manifestsDir := resolveManifestsDir(dataDirOverride)

	helmChartConfigFile := componentName + "-config-rke2-patcher.yaml"
	helmChartConfigName := defaultChartConfigName
	namespace := envOrDefault(helmNamespaceEnv, defaultNamespace)

	filePath := filepath.Join(manifestsDir, helmChartConfigFile)
	content := renderHelmChartConfig(componentName, helmChartConfigName, namespace, imageName, imageTag)

	return filePath, content
}

func resolveManifestsDir(dataDirOverride string) string {
	trimmedDataDirOverride := strings.TrimSpace(dataDirOverride)
	if trimmedDataDirOverride != "" {
		return filepath.Join(trimmedDataDirOverride, "server", "manifests")
	}

	dataDir := envOrDefault(dataDirEnv, defaultDataDir)
	return filepath.Join(dataDir, "server", "manifests")
}

func MergeHelmChartConfigWithContents(generatedContent string, existingContents []string) (string, error) {
	generatedDoc, err := parseSingleHelmChartConfig(generatedContent)
	if err != nil {
		return "", fmt.Errorf("failed to parse generated HelmChartConfig: %w", err)
	}

	targetName := strings.TrimSpace(generatedDoc.Metadata.Name)
	targetNamespace := strings.TrimSpace(generatedDoc.Metadata.Namespace)
	if targetName == "" || targetNamespace == "" {
		return "", fmt.Errorf("generated HelmChartConfig is missing metadata.name or metadata.namespace")
	}

	mergedSpec := map[string]any{}
	for _, content := range existingContents {
		spec, found, err := findMatchingSpecInContent(content, targetName, targetNamespace)
		if err != nil {
			return "", err
		}
		if !found {
			continue
		}

		mergedSpec = deepMergeMaps(mergedSpec, spec)
	}

	generatedSpec := generatedDoc.Spec
	if generatedSpec == nil {
		generatedSpec = map[string]any{}
	}

	existingValues, hasExistingValues := stringField(mergedSpec, "valuesContent")
	newValues, hasNewValues := stringField(generatedSpec, "valuesContent")
	if hasExistingValues && hasNewValues {
		combinedValues, err := mergeValuesContent(existingValues, newValues)
		if err != nil {
			return "", err
		}
		generatedSpec["valuesContent"] = combinedValues
	}

	mergedSpec = deepMergeMaps(mergedSpec, generatedSpec)

	mergedDoc := helmChartConfigDoc{
		APIVersion: generatedDoc.APIVersion,
		Kind:       generatedDoc.Kind,
		Metadata: metadataRef{
			Name:      generatedDoc.Metadata.Name,
			Namespace: generatedDoc.Metadata.Namespace,
		},
		Spec: mergedSpec,
	}

	if strings.TrimSpace(mergedDoc.APIVersion) == "" {
		mergedDoc.APIVersion = "helm.cattle.io/v1"
	}
	if strings.TrimSpace(mergedDoc.Kind) == "" {
		mergedDoc.Kind = "HelmChartConfig"
	}

	b, err := yaml.Marshal(mergedDoc)
	if err != nil {
		return "", err
	}

	if len(b) == 0 || b[len(b)-1] != '\n' {
		b = append(b, '\n')
	}

	return string(b), nil
}

func HelmChartConfigIdentityFromContent(content string) (string, string, error) {
	doc, err := parseSingleHelmChartConfig(content)
	if err != nil {
		return "", "", err
	}

	name := strings.TrimSpace(doc.Metadata.Name)
	namespace := strings.TrimSpace(doc.Metadata.Namespace)
	if name == "" || namespace == "" {
		return "", "", fmt.Errorf("HelmChartConfig content missing metadata.name or metadata.namespace")
	}

	return name, namespace, nil
}

type helmChartConfigDoc struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   metadataRef    `yaml:"metadata"`
	Spec       map[string]any `yaml:"spec,omitempty"`
}

type metadataRef struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

func parseSingleHelmChartConfig(content string) (helmChartConfigDoc, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	for {
		var doc helmChartConfigDoc
		err := decoder.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return helmChartConfigDoc{}, err
		}

		if strings.EqualFold(strings.TrimSpace(doc.Kind), "HelmChartConfig") {
			return doc, nil
		}
	}

	return helmChartConfigDoc{}, fmt.Errorf("no HelmChartConfig document found")
}

func findMatchingSpecInContent(content string, targetName string, targetNamespace string) (map[string]any, bool, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))

	for {
		var doc helmChartConfigDoc
		err := decoder.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, fmt.Errorf("failed parsing HelmChartConfig content: %w", err)
		}

		if !strings.EqualFold(strings.TrimSpace(doc.Kind), "HelmChartConfig") {
			continue
		}

		if strings.TrimSpace(doc.Metadata.Name) == targetName && strings.TrimSpace(doc.Metadata.Namespace) == targetNamespace {
			if doc.Spec == nil {
				return map[string]any{}, true, nil
			}
			return deepCopyMap(doc.Spec), true, nil
		}
	}

	return nil, false, nil
}

func deepMergeMaps(base map[string]any, overlay map[string]any) map[string]any {
	result := deepCopyMap(base)
	if result == nil {
		result = map[string]any{}
	}

	for key, overlayValue := range overlay {
		baseValue, found := result[key]
		if found {
			baseMap, baseIsMap := baseValue.(map[string]any)
			overlayMap, overlayIsMap := overlayValue.(map[string]any)
			if baseIsMap && overlayIsMap {
				result[key] = deepMergeMaps(baseMap, overlayMap)
				continue
			}
		}

		result[key] = deepCopyValue(overlayValue)
	}

	return result
}

func deepCopyMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}

	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = deepCopyValue(value)
	}

	return result
}

func deepCopyValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return deepCopyMap(typed)
	case []any:
		copied := make([]any, len(typed))
		for i := range typed {
			copied[i] = deepCopyValue(typed[i])
		}
		return copied
	default:
		return typed
	}
}

func stringField(spec map[string]any, field string) (string, bool) {
	if spec == nil {
		return "", false
	}

	raw, found := spec[field]
	if !found {
		return "", false
	}

	value, ok := raw.(string)
	if !ok {
		return "", false
	}

	return value, true
}

func mergeValuesContent(existing string, incoming string) (string, error) {
	existingTrimmed := strings.TrimSpace(existing)
	incomingTrimmed := strings.TrimSpace(incoming)

	if existingTrimmed == "" {
		return incoming, nil
	}
	if incomingTrimmed == "" {
		return existing, nil
	}

	var existingValues any
	if err := yaml.Unmarshal([]byte(existing), &existingValues); err != nil {
		return "", fmt.Errorf("failed to parse existing valuesContent: %w", err)
	}

	var incomingValues any
	if err := yaml.Unmarshal([]byte(incoming), &incomingValues); err != nil {
		return "", fmt.Errorf("failed to parse generated valuesContent: %w", err)
	}

	mergedValues := deepMergeValue(existingValues, incomingValues)
	b, err := yaml.Marshal(mergedValues)
	if err != nil {
		return "", err
	}

	return strings.TrimRight(string(b), "\n"), nil
}

func deepMergeValue(base any, overlay any) any {
	baseMap, baseIsMap := base.(map[string]any)
	overlayMap, overlayIsMap := overlay.(map[string]any)
	if baseIsMap && overlayIsMap {
		return deepMergeMaps(baseMap, overlayMap)
	}

	return deepCopyValue(overlay)
}

func renderHelmChartConfig(componentName string, chartName string, namespace string, imageName string, imageTag string) string {
	valuesContent := renderValuesContent(componentName, chartName, imageName, imageTag)

	return fmt.Sprintf(`apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: %s
  namespace: %s
spec:
  valuesContent: |-
%s
`, chartName, namespace, valuesContent)
}

func renderValuesContent(componentName string, chartName string, imageName string, imageTag string) string {
	if strings.EqualFold(strings.TrimSpace(componentName), "calico-operator") || strings.EqualFold(strings.TrimSpace(chartName), "rke2-calico") {
		image := imageRepositoryWithoutRegistry(imageName)
		if image == "" {
			image = strings.TrimSpace(imageName)
		}

		registryHost := configuredRegistryHost()

		return fmt.Sprintf(`    tigeraOperator:
      image: %s
      version: %s
	      registry: %s`, image, imageTag, registryHost)
	}

	if strings.EqualFold(strings.TrimSpace(componentName), "ingress-nginx") || strings.EqualFold(strings.TrimSpace(chartName), "rke2-ingress-nginx") {
		return fmt.Sprintf(`    controller:
      image:
        repository: %s
        tag: %s`, imageName, imageTag)
	}

	if strings.EqualFold(strings.TrimSpace(componentName), "cilium-operator") || strings.EqualFold(strings.TrimSpace(chartName), "rke2-cilium") {
		repository := strings.TrimSuffix(strings.TrimSpace(imageName), "-generic")
		if repository == "" {
			repository = imageName
		}

		return fmt.Sprintf(`    operator:
      image:
        repository: %s
        tag: %s`, repository, imageTag)
	}

	if strings.EqualFold(strings.TrimSpace(componentName), "canal") || strings.EqualFold(strings.TrimSpace(componentName), "canal-calico") {
		return fmt.Sprintf(`    calico:
      cniImage:
        repository: %s
        tag: %s
      nodeImage:
        repository: %s
        tag: %s
      flexvolImage:
        repository: %s
        tag: %s
      kubeControllerImage:
        repository: %s
        tag: %s`, imageName, imageTag, imageName, imageTag, imageName, imageTag, imageName, imageTag)
	}

	if strings.EqualFold(strings.TrimSpace(componentName), "canal-flannel") {
		return fmt.Sprintf(`    flannel:
		image:
		  repository: %s
		  tag: %s`, imageName, imageTag)
	}

	return fmt.Sprintf(`    image:
      repository: %s
      tag: %s`, imageName, imageTag)
}

func envOrDefault(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	return value
}

func configuredRegistryHost() string {
	rawValue := strings.TrimSpace(os.Getenv(registryEnv))
	if rawValue == "" {
		rawValue = defaultRegistryHost
	}

	host := registryHostFromValue(rawValue)
	if strings.TrimSpace(host) == "" {
		return defaultRegistryHost
	}

	return host
}

func registryHostFromValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	if strings.Contains(trimmed, "://") {
		parsed, err := url.Parse(trimmed)
		if err == nil {
			host := strings.TrimSpace(parsed.Host)
			if host != "" {
				return host
			}
		}
	}

	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		return ""
	}

	firstSlash := strings.Index(trimmed, "/")
	if firstSlash >= 0 {
		return strings.TrimSpace(trimmed[:firstSlash])
	}

	return trimmed
}

func imageRepositoryWithoutRegistry(imageName string) string {
	trimmed := strings.TrimSpace(imageName)
	if trimmed == "" {
		return ""
	}

	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return trimmed
	}

	first := strings.ToLower(parts[0])
	hasRegistryPrefix := strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost"
	if !hasRegistryPrefix {
		return trimmed
	}

	return strings.Join(parts[1:], "/")
}
