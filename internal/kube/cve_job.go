package kube

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	cveNamespaceEnv      = "RKE2_PATCHER_CVE_NAMESPACE"
	cveScannerImageEnv   = "RKE2_PATCHER_CVE_SCANNER_IMAGE"
	cveJobTimeoutEnv     = "RKE2_PATCHER_CVE_JOB_TIMEOUT"
	defaultCVENamespace  = "rke2-patcher"
	defaultCVEScanImage  = "aquasec/trivy:latest"
	defaultCVEJobTimeout = 8 * time.Minute
)

type scanJobStatus struct {
	Succeeded  int32
	Failed     int32
	Conditions []scanJobCondition
}

type scanJobCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

type scanJobResponse struct {
	Status struct {
		Succeeded  int32              `json:"succeeded"`
		Failed     int32              `json:"failed"`
		Conditions []scanJobCondition `json:"conditions"`
	} `json:"status"`
}

type scanPodList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	} `json:"items"`
}

const (
	batchScanBeginPrefix = "__RKE2_PATCHER_TRIVY_BEGIN__"
	batchScanRCPrefix    = "__RKE2_PATCHER_TRIVY_RC__"
	batchScanEndPrefix   = "__RKE2_PATCHER_TRIVY_END__"
	clusterVEXFilePath   = "/tmp/rancher.openvex.json"
)

var trivyVEXDownloadScriptLines = []string{
	"VEX_FILE=\"/tmp/rancher.openvex.json\"",
	"VEX_URL=\"https://raw.githubusercontent.com/rancher/vexhub/refs/heads/main/reports/rancher.openvex.json\"",
	"download_vex() {",
	"  if command -v curl >/dev/null 2>&1; then",
	"    curl -fsSL \"${VEX_URL}\" -o \"${VEX_FILE}\"",
	"    return $?",
	"  fi",
	"  if command -v wget >/dev/null 2>&1; then",
	"    wget -qO \"${VEX_FILE}\" \"${VEX_URL}\"",
	"    return $?",
	"  fi",
	"  echo \"neither curl nor wget found to download rancher.openvex.json\" >&2",
	"  return 1",
	"}",
	"attempt=1",
	"max_attempts=3",
	"while [ \"${attempt}\" -le \"${max_attempts}\" ]; do",
	"  if download_vex; then",
	"    break",
	"  fi",
	"  if [ \"${attempt}\" -eq \"${max_attempts}\" ]; then",
	"    echo \"failed to download rancher.openvex.json after ${max_attempts} attempts\" >&2",
	"    exit 1",
	"  fi",
	"  sleep \"${attempt}\"",
	"  attempt=$((attempt + 1))",
	"done",
}

func ScanImageWithTrivyJob(image string, showProgress bool) ([]byte, error) {
	targetImage := strings.TrimSpace(image)
	if targetImage == "" {
		return nil, fmt.Errorf("target image cannot be empty")
	}

	api, err := kubeAPIClient()
	if err != nil {
		return nil, err
	}

	namespace := strings.TrimSpace(os.Getenv(cveNamespaceEnv))
	if namespace == "" {
		namespace = defaultCVENamespace
	}

	if err := ensureNamespaceForScanJob(api, namespace); err != nil {
		return nil, err
	}

	if showProgress {
		fmt.Println("Checking CVEs with in-cluster scanner job. Please wait...")
	}

	scannerImage := strings.TrimSpace(os.Getenv(cveScannerImageEnv))
	if scannerImage == "" {
		scannerImage = defaultCVEScanImage
	}

	timeout := defaultCVEJobTimeout
	if configured := strings.TrimSpace(os.Getenv(cveJobTimeoutEnv)); configured != "" {
		parsedTimeout, parseErr := time.ParseDuration(configured)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid %s value %q: %w", cveJobTimeoutEnv, configured, parseErr)
		}
		if parsedTimeout <= 0 {
			return nil, fmt.Errorf("invalid %s value %q: must be greater than zero", cveJobTimeoutEnv, configured)
		}
		timeout = parsedTimeout
	}

	jobName := fmt.Sprintf("rke2-patcher-cve-%d", time.Now().UnixNano())
	if err := createScanJob(api, namespace, jobName, scannerImage, targetImage); err != nil {
		return nil, err
	}
	defer func() {
		_ = deleteJob(api, namespace, jobName)
	}()

	return waitForScanJobCompletion(api, namespace, jobName, timeout)
}

func ScanImagesWithTrivyJob(images []string, showProgress bool) ([]byte, error) {
	targetImages := make([]string, 0, len(images))
	for _, image := range images {
		trimmed := strings.TrimSpace(image)
		if trimmed == "" {
			continue
		}
		targetImages = append(targetImages, trimmed)
	}

	if len(targetImages) == 0 {
		return nil, fmt.Errorf("target images cannot be empty")
	}

	api, err := kubeAPIClient()
	if err != nil {
		return nil, err
	}

	namespace := strings.TrimSpace(os.Getenv(cveNamespaceEnv))
	if namespace == "" {
		namespace = defaultCVENamespace
	}

	if err := ensureNamespaceForScanJob(api, namespace); err != nil {
		return nil, err
	}

	if showProgress {
		fmt.Printf("Checking CVEs with in-cluster scanner job for %d images. Please wait...\n", len(targetImages))
	}

	scannerImage := strings.TrimSpace(os.Getenv(cveScannerImageEnv))
	if scannerImage == "" {
		scannerImage = defaultCVEScanImage
	}

	timeout := defaultCVEJobTimeout
	if configured := strings.TrimSpace(os.Getenv(cveJobTimeoutEnv)); configured != "" {
		parsedTimeout, parseErr := time.ParseDuration(configured)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid %s value %q: %w", cveJobTimeoutEnv, configured, parseErr)
		}
		if parsedTimeout <= 0 {
			return nil, fmt.Errorf("invalid %s value %q: must be greater than zero", cveJobTimeoutEnv, configured)
		}
		timeout = parsedTimeout
	}

	jobName := fmt.Sprintf("rke2-patcher-cve-batch-%d", time.Now().UnixNano())
	if err := createBatchScanJob(api, namespace, jobName, scannerImage, targetImages); err != nil {
		return nil, err
	}
	defer func() {
		_ = deleteJob(api, namespace, jobName)
	}()

	return waitForScanJobCompletion(api, namespace, jobName, timeout)
}

func waitForScanJobCompletion(api kubeAPI, namespace string, jobName string, timeout time.Duration) ([]byte, error) {

	deadline := time.Now().Add(timeout)
	for {
		status, statusErr := getScanJobStatus(api, namespace, jobName)
		if statusErr != nil {
			return nil, statusErr
		}

		if status.Succeeded > 0 {
			logs, logsErr := waitForJobLogs(api, namespace, jobName, 20*time.Second)
			if logsErr != nil {
				return nil, fmt.Errorf("scan job %s succeeded but logs are unavailable: %w", jobName, logsErr)
			}
			return logs, nil
		}

		if status.Failed > 0 {
			logs, logsErr := waitForJobLogs(api, namespace, jobName, 8*time.Second)
			if logsErr != nil {
				return nil, fmt.Errorf("scan job %s failed: %s", jobName, status.failureReason())
			}
			trimmedLogs := strings.TrimSpace(string(logs))
			if trimmedLogs == "" {
				return nil, fmt.Errorf("scan job %s failed: %s", jobName, status.failureReason())
			}
			return nil, fmt.Errorf("scan job %s failed: %s\n%s", jobName, status.failureReason(), trimmedLogs)
		}

		if time.Now().After(deadline) {
			logs, _ := waitForJobLogs(api, namespace, jobName, 3*time.Second)
			trimmedLogs := strings.TrimSpace(string(logs))
			if trimmedLogs == "" {
				return nil, fmt.Errorf("scan job %s timed out after %s", jobName, timeout)
			}
			return nil, fmt.Errorf("scan job %s timed out after %s; partial logs:\n%s", jobName, timeout, trimmedLogs)
		}

		time.Sleep(2 * time.Second)
	}
}

func (s scanJobStatus) failureReason() string {
	for _, condition := range s.Conditions {
		if condition.Type == "Failed" && strings.EqualFold(condition.Status, "True") {
			if strings.TrimSpace(condition.Message) != "" {
				return condition.Message
			}
			if strings.TrimSpace(condition.Reason) != "" {
				return condition.Reason
			}
		}
	}
	return "job reported failed status"
}

func createScanJob(api kubeAPI, namespace string, jobName string, scannerImage string, targetImage string) error {
	requestURL := fmt.Sprintf("%s/apis/batch/v1/namespaces/%s/jobs", api.BaseURL, url.PathEscape(namespace))

	scriptLines := append([]string{}, trivyVEXDownloadScriptLines...)
	scriptLines = append(scriptLines, fmt.Sprintf("trivy image --quiet --format json --severity CRITICAL,HIGH --vex %q %q", clusterVEXFilePath, targetImage))
	script := strings.Join(scriptLines, "\n")

	body := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": map[string]any{
			"name":      jobName,
			"namespace": namespace,
			"labels": map[string]string{
				"app.kubernetes.io/name": "rke2-patcher",
				"rke2-patcher.cve":       "true",
			},
		},
		"spec": map[string]any{
			"backoffLimit": int32(0),
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]string{
						"app.kubernetes.io/name": "rke2-patcher",
						"rke2-patcher.cve":       "true",
					},
				},
				"spec": map[string]any{
					"restartPolicy": "Never",
					"containers": []map[string]any{
						{
							"name":            "scanner",
							"image":           scannerImage,
							"imagePullPolicy": "IfNotPresent",
							"command":         []string{"sh"},
							"args":            []string{"-c", script},
						},
					},
				},
			},
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(api.AuthHeader) != "" {
		req.Header.Set("Authorization", api.AuthHeader)
	}

	resp, err := api.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("failed to create scan job %s/%s: status %d: %s", namespace, jobName, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	return nil
}

func createBatchScanJob(api kubeAPI, namespace string, jobName string, scannerImage string, targetImages []string) error {
	requestURL := fmt.Sprintf("%s/apis/batch/v1/namespaces/%s/jobs", api.BaseURL, url.PathEscape(namespace))

	scriptLines := append([]string{}, trivyVEXDownloadScriptLines...)
	scriptLines = append(scriptLines, []string{
		"for image in \"$@\"; do",
		"  echo \"" + batchScanBeginPrefix + "${image}\"",
		"  trivy image --quiet --format json --severity CRITICAL,HIGH --vex \"${VEX_FILE}\" \"${image}\" 2>&1",
		"  rc=$?",
		"  echo \"" + batchScanRCPrefix + "${image}__${rc}\"",
		"  echo \"" + batchScanEndPrefix + "${image}\"",
		"done",
	}...)
	script := strings.Join(scriptLines, "\n")

	containerArgs := []string{"-c", script, "--"}
	containerArgs = append(containerArgs, targetImages...)

	body := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": map[string]any{
			"name":      jobName,
			"namespace": namespace,
			"labels": map[string]string{
				"app.kubernetes.io/name": "rke2-patcher",
				"rke2-patcher.cve":       "true",
			},
		},
		"spec": map[string]any{
			"backoffLimit": int32(0),
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]string{
						"app.kubernetes.io/name": "rke2-patcher",
						"rke2-patcher.cve":       "true",
					},
				},
				"spec": map[string]any{
					"restartPolicy": "Never",
					"containers": []map[string]any{
						{
							"name":            "scanner",
							"image":           scannerImage,
							"imagePullPolicy": "IfNotPresent",
							"command":         []string{"sh"},
							"args":            containerArgs,
						},
					},
				},
			},
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(api.AuthHeader) != "" {
		req.Header.Set("Authorization", api.AuthHeader)
	}

	resp, err := api.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("failed to create batch scan job %s/%s: status %d: %s", namespace, jobName, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	return nil
}

func ensureNamespaceForScanJob(api kubeAPI, namespace string) error {
	exists, err := namespaceExists(api, namespace)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	fmt.Printf("Namespace %q does not exist. Do you want to create it? [Yes/No]: ", namespace)
	approved, err := promptYesNo()
	if err != nil {
		return err
	}
	if !approved {
		return fmt.Errorf("namespace %q not found and creation was not approved", namespace)
	}

	if err := createNamespace(api, namespace); err != nil {
		return err
	}

	fmt.Printf("Namespace %q created.\n", namespace)
	return nil
}

func namespaceExists(api kubeAPI, namespace string) (bool, error) {
	requestURL := fmt.Sprintf("%s/api/v1/namespaces/%s", api.BaseURL, url.PathEscape(namespace))

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(api.AuthHeader) != "" {
		req.Header.Set("Authorization", api.AuthHeader)
	}

	resp, err := api.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return false, fmt.Errorf("failed to check namespace %q: status %d: %s", namespace, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
}

func createNamespace(api kubeAPI, namespace string) error {
	requestURL := fmt.Sprintf("%s/api/v1/namespaces", api.BaseURL)
	body := map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]string{
			"name": namespace,
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(api.AuthHeader) != "" {
		req.Header.Set("Authorization", api.AuthHeader)
	}

	resp, err := api.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusConflict {
		return nil
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("failed to create namespace %q: status %d: %s", namespace, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
}

func promptYesNo() (bool, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		input, err := reader.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("failed to read user input: %w", err)
		}

		normalized := strings.ToLower(strings.TrimSpace(input))
		switch normalized {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Print("Please answer Yes or No: ")
		}
	}
}

func getScanJobStatus(api kubeAPI, namespace string, jobName string) (scanJobStatus, error) {
	requestURL := fmt.Sprintf("%s/apis/batch/v1/namespaces/%s/jobs/%s", api.BaseURL, url.PathEscape(namespace), url.PathEscape(jobName))

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return scanJobStatus{}, err
	}
	if strings.TrimSpace(api.AuthHeader) != "" {
		req.Header.Set("Authorization", api.AuthHeader)
	}

	resp, err := api.Client.Do(req)
	if err != nil {
		return scanJobStatus{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return scanJobStatus{}, fmt.Errorf("failed to fetch scan job %s/%s: status %d: %s", namespace, jobName, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var response scanJobResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return scanJobStatus{}, err
	}

	return scanJobStatus{
		Succeeded:  response.Status.Succeeded,
		Failed:     response.Status.Failed,
		Conditions: response.Status.Conditions,
	}, nil
}

func waitForJobLogs(api kubeAPI, namespace string, jobName string, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error

	for {
		podName, findErr := findJobPodName(api, namespace, jobName)
		if findErr != nil {
			lastErr = findErr
		} else if podName != "" {
			logs, logsErr := podLogs(api, namespace, podName)
			if logsErr == nil {
				return logs, nil
			}
			lastErr = logsErr
		}

		if time.Now().After(deadline) {
			if lastErr == nil {
				return nil, fmt.Errorf("timed out waiting for logs of job %s/%s", namespace, jobName)
			}
			return nil, lastErr
		}

		time.Sleep(time.Second)
	}
}

func findJobPodName(api kubeAPI, namespace string, jobName string) (string, error) {
	requestURL := fmt.Sprintf("%s/api/v1/namespaces/%s/pods?labelSelector=%s", api.BaseURL, url.PathEscape(namespace), url.QueryEscape("job-name="+jobName))

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

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("failed to list pods for job %s/%s: status %d: %s", namespace, jobName, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var list scanPodList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return "", err
	}

	if len(list.Items) == 0 {
		return "", nil
	}

	sort.Slice(list.Items, func(i int, j int) bool {
		return list.Items[i].Metadata.Name < list.Items[j].Metadata.Name
	})

	for _, item := range list.Items {
		phase := strings.TrimSpace(item.Status.Phase)
		if phase == "Succeeded" || phase == "Failed" || phase == "Running" {
			return item.Metadata.Name, nil
		}
	}

	return list.Items[0].Metadata.Name, nil
}

func podLogs(api kubeAPI, namespace string, podName string) ([]byte, error) {
	requestURL := fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s/log?container=scanner", api.BaseURL, url.PathEscape(namespace), url.PathEscape(podName))

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(api.AuthHeader) != "" {
		req.Header.Set("Authorization", api.AuthHeader)
	}

	resp, err := api.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("failed to read logs for pod %s/%s: status %d: %s", namespace, podName, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	return io.ReadAll(resp.Body)
}

func deleteJob(api kubeAPI, namespace string, jobName string) error {
	requestURL := fmt.Sprintf("%s/apis/batch/v1/namespaces/%s/jobs/%s?propagationPolicy=Background", api.BaseURL, url.PathEscape(namespace), url.PathEscape(jobName))

	req, err := http.NewRequest(http.MethodDelete, requestURL, nil)
	if err != nil {
		return err
	}
	if strings.TrimSpace(api.AuthHeader) != "" {
		req.Header.Set("Authorization", api.AuthHeader)
	}

	resp, err := api.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
		return nil
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("failed to delete scan job %s/%s: status %d: %s", namespace, jobName, resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
}
