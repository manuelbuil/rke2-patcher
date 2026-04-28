package docker

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const scannerNamespace = "rke2-patcher"
const nodePatcherBinaryPath = "/usr/local/bin/rke2-patcher-test"

type TestConfig struct {
	TestDir        string
	KubeconfigFile string
	PatcherBinary  string
	RKE2Version    string
	ServerConfig   string
	Server         DockerNode
}

type DockerNode struct {
	Name string
	Port int
}

func NewTestConfig(version string, patcherBinary string) (*TestConfig, error) {
	if strings.TrimSpace(version) == "" {
		return nil, fmt.Errorf("rke2 version cannot be empty")
	}
	if strings.TrimSpace(patcherBinary) == "" {
		return nil, fmt.Errorf("patcher binary path cannot be empty")
	}

	resolvedBinary, err := resolvePatcherBinaryPath(patcherBinary)
	if err != nil {
		return nil, err
	}

	tempDir, err := os.MkdirTemp("", "rke2-patcher-docker-test-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	return &TestConfig{
		TestDir:       tempDir,
		PatcherBinary: resolvedBinary,
		RKE2Version:   version,
	}, nil
}

func resolvePatcherBinaryPath(patcherBinary string) (string, error) {
	trimmed := strings.TrimSpace(patcherBinary)
	if trimmed == "" {
		return "", fmt.Errorf("patcher binary path cannot be empty")
	}

	if filepath.IsAbs(trimmed) {
		if _, err := os.Stat(trimmed); err != nil {
			return "", fmt.Errorf("patcher binary %q is not accessible: %w", trimmed, err)
		}
		return trimmed, nil
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory while resolving patcher binary: %w", err)
	}

	currentDir := workingDir
	for {
		candidate := filepath.Join(currentDir, trimmed)
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Abs(candidate)
		}

		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			break
		}
		currentDir = parentDir
	}

	return "", fmt.Errorf("patcher binary %q not found from working directory %q or any parent directory", trimmed, workingDir)
}

func (config *TestConfig) InstallTrivyLocally(version string) error {
	installCmd := fmt.Sprintf("curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin v%s", version)
	if out, err := config.Server.RunCmdOnNode(installCmd); err != nil {
		return fmt.Errorf("failed to install trivy: %s: %w", out, err)
	}
	return nil
}

func (config *TestConfig) CheckTrivyVersion() (string, error) {
	installCmd := "trivy --version"
	out, err := config.Server.RunCmdOnNode(installCmd)
	if err != nil {
		return "", fmt.Errorf("failed to check trivy version: %s: %w", out, err)
	}
	return out, nil
}

func (config *TestConfig) ProvisionServer() error {
	serverName := fmt.Sprintf("rke2-server-%d", time.Now().UnixNano())
	port := getPort()
	if port <= 0 {
		return fmt.Errorf("failed to find free API port")
	}

	config.Server = DockerNode{Name: serverName, Port: port}

	_, _ = RunCommand(fmt.Sprintf("docker rm -f %s", serverName))

	dockerRun := strings.Join([]string{
		"docker run -d",
		"--name", serverName,
		"--hostname", serverName,
		"--privileged",
		"--cgroupns=host",
		"--memory", "4096m",
		"-p", fmt.Sprintf("127.0.0.1:%d:6443", port),
		"-e", "RKE2_TOKEN=testtoken",
		"-v", "/sys/fs/bpf:/sys/fs/bpf",
		"-v", "/lib/modules:/lib/modules",
		"-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
		"rancher/systemd-node:v0.0.5",
		"/usr/lib/systemd/systemd --unit=noop.target --show-status=true",
	}, " ")

	if out, err := RunCommand(dockerRun); err != nil {
		return fmt.Errorf("failed to start systemd node container: %s: %w", out, err)
	}

	if out, err := config.Server.RunCmdOnNode("mount --make-rshared /sys"); err != nil {
		return fmt.Errorf("failed to set /sys mount propagation: %s: %w", out, err)
	}

	installCmd := fmt.Sprintf("curl -sfL https://get.rke2.io | INSTALL_RKE2_VERSION='%s' sh -", config.RKE2Version)
	if out, err := config.Server.RunCmdOnNode(installCmd); err != nil {
		return fmt.Errorf("failed to install rke2 server: %s: %w", out, err)
	}

	// Always set prime: true, and append any extra config provided by the test
	extraConfig := strings.TrimSpace(config.ServerConfig)
	mergedConfig := "prime: true\n"
	if extraConfig != "" {
		mergedConfig += "\n" + extraConfig + "\n"
	}

	if err := config.writeServerConfig(mergedConfig); err != nil {
		return err
	}

	if out, err := config.Server.RunCmdOnNode("systemctl enable --now rke2-server"); err != nil {
		return fmt.Errorf("failed to enable/start rke2-server: %s: %w", out, err)
	}

	if err := config.waitForKubeconfig(7 * time.Minute); err != nil {
		return err
	}

	if err := config.CopyAndModifyKubeconfig(); err != nil {
		return err
	}

	if err := config.CopyPatcherBinaryToServer(); err != nil {
		return err
	}

	return nil
}

func (config *TestConfig) CopyPatcherBinaryToServer() error {
	if strings.TrimSpace(config.Server.Name) == "" {
		return fmt.Errorf("server is not provisioned")
	}

	copyCmd := fmt.Sprintf("docker cp %s %s:%s", config.PatcherBinary, config.Server.Name, nodePatcherBinaryPath)
	if out, err := RunCommand(copyCmd); err != nil {
		return fmt.Errorf("failed to copy patcher binary into server: %s: %w", out, err)
	}

	if out, err := config.Server.RunCmdOnNode("chmod +x " + nodePatcherBinaryPath); err != nil {
		return fmt.Errorf("failed to chmod patcher binary in server: %s: %w", out, err)
	}

	return nil
}

func (config *TestConfig) WaitForDefaultComponents() error {
	deployments := []string{
		"rke2-coredns-rke2-coredns",
		"rke2-coredns-rke2-coredns-autoscaler",
		"rke2-metrics-server",
		"rke2-snapshot-controller",
	}
	daemonsets := []string{
		"rke2-canal",
		"rke2-ingress-nginx-controller",
	}

	for _, deployment := range deployments {
		cmd := fmt.Sprintf("-n kube-system rollout status deployment/%s --timeout=300s", deployment)
		if out, err := config.Server.RunKubectl(cmd); err != nil {
			return fmt.Errorf("deployment %s did not become ready: %s: %w", deployment, out, err)
		}
	}

	for _, daemonset := range daemonsets {
		cmd := fmt.Sprintf("-n kube-system rollout status daemonset/%s --timeout=300s", daemonset)
		if out, err := config.Server.RunKubectl(cmd); err != nil {
			return fmt.Errorf("daemonset %s did not become ready: %s: %w", daemonset, out, err)
		}
	}

	return nil
}

func (config *TestConfig) CheckDefaultDeploymentsAndDaemonSets() error {
	deployments := []string{
		"rke2-coredns-rke2-coredns",
		"rke2-coredns-rke2-coredns-autoscaler",
		"rke2-metrics-server",
		"rke2-snapshot-controller",
	}
	daemonsets := []string{
		"rke2-canal",
		"rke2-ingress-nginx-controller",
	}

	for _, deployment := range deployments {
		cmd := fmt.Sprintf("-n kube-system rollout status deployment/%s --timeout=10s", deployment)
		if out, err := config.Server.RunKubectl(cmd); err != nil {
			return fmt.Errorf("deployment %s not ready yet: %s: %w", deployment, out, err)
		}
	}

	for _, daemonset := range daemonsets {
		cmd := fmt.Sprintf("-n kube-system rollout status daemonset/%s --timeout=10s", daemonset)
		if out, err := config.Server.RunKubectl(cmd); err != nil {
			return fmt.Errorf("daemonset %s not ready yet: %s: %w", daemonset, out, err)
		}
	}

	return nil
}

func (config *TestConfig) CheckDefaultAndTraefikDeploymentsAndDaemonSets() error {
	deployments := []string{
		"rke2-coredns-rke2-coredns",
		"rke2-coredns-rke2-coredns-autoscaler",
		"rke2-metrics-server",
		"rke2-snapshot-controller",
	}
	daemonsets := []string{
		"rke2-canal",
		"rke2-traefik",
	}

	for _, deployment := range deployments {
		cmd := fmt.Sprintf("-n kube-system rollout status deployment/%s --timeout=10s", deployment)
		if out, err := config.Server.RunKubectl(cmd); err != nil {
			return fmt.Errorf("deployment %s not ready yet: %s: %w", deployment, out, err)
		}
	}

	for _, daemonset := range daemonsets {
		cmd := fmt.Sprintf("-n kube-system rollout status daemonset/%s --timeout=10s", daemonset)
		if out, err := config.Server.RunKubectl(cmd); err != nil {
			return fmt.Errorf("daemonset %s not ready yet: %s: %w", daemonset, out, err)
		}
	}

	return nil
}

func (config *TestConfig) CheckFlannelTraefikDeploymentsAndDaemonSets() error {
	if out, err := config.Server.RunKubectl("-n kube-system rollout status daemonset/kube-flannel-ds --timeout=10s"); err != nil {
		return fmt.Errorf("daemonset kube-flannel-ds not ready yet: %s: %w", out, err)
	}

	if out, err := config.Server.RunKubectl("-n kube-system rollout status daemonset/rke2-traefik --timeout=10s"); err != nil {
		return fmt.Errorf("daemonset rke2-traefik not ready yet: %s: %w", out, err)
	}

	return nil
}

// CheckNodeLocalDNS verifies that the node-local-dns DaemonSet is ready in kube-system namespace.
func (config *TestConfig) CheckNodeLocalDNS() error {
	cmd := "-n kube-system rollout status daemonset/node-local-dns --timeout=30s"
	if out, err := config.Server.RunKubectl(cmd); err != nil {
		return fmt.Errorf("daemonset node-local-dns not ready: %s: %w", out, err)
	}
	return nil
}

// CheckTraefikGwAPI verifies rke2-traefik DaemonSet is ready and logs contain 'providerName=kubernetesgateway'.
func (config *TestConfig) CheckTraefikGwAPI() error {
	// Check DaemonSet readiness
	cmd := "-n kube-system rollout status daemonset/rke2-traefik --timeout=30s"
	if out, err := config.Server.RunKubectl(cmd); err != nil {
		return fmt.Errorf("daemonset rke2-traefik not ready: %s: %w", out, err)
	}

	// Get pod names for rke2-traefik
	getPodsCmd := "-n kube-system get pods -l app.kubernetes.io/name=rke2-traefik -o jsonpath='{.items[*].metadata.name}'"
	podsOut, err := config.Server.RunKubectl(getPodsCmd)
	if err != nil {
		return fmt.Errorf("failed to get rke2-traefik pods: %w", err)
	}
	pods := strings.Fields(strings.Trim(podsOut, "'\n "))
	if len(pods) == 0 {
		return fmt.Errorf("no rke2-traefik pods found")
	}

	// Check logs for each pod
	found := false
	for _, pod := range pods {
		logCmd := fmt.Sprintf("-n kube-system logs %s", pod)
		logs, err := config.Server.RunKubectl(logCmd)
		if err != nil {
			continue // try next pod
		}
		if strings.Contains(logs, "kubernetesgateway") {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("rke2-traefik logs do not contain 'kubernetesgateway'")
	}
	return nil
}

func (config *TestConfig) CheckNodesReady(expectedNodes int) error {
	out, err := config.Server.RunKubectl("get nodes --no-headers")
	if err != nil {
		return fmt.Errorf("failed to get nodes: %w", err)
	}

	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return fmt.Errorf("no nodes returned by kubectl")
	}

	lines := strings.Split(trimmed, "\n")
	if expectedNodes > 0 && len(lines) != expectedNodes {
		return fmt.Errorf("expected %d node(s), found %d", expectedNodes, len(lines))
	}

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return fmt.Errorf("failed to parse node line %q", line)
		}
		status := fields[1]
		if !strings.HasPrefix(status, "Ready") {
			return fmt.Errorf("node %s not ready yet (status=%s)", fields[0], status)
		}
	}

	return nil
}

func (config *TestConfig) WaitForDeploymentReady(namespace, name string, timeout time.Duration) error {
	timeoutArg := fmt.Sprintf("%ds", int(timeout.Seconds()))
	cmd := fmt.Sprintf("-n %s rollout status deployment/%s --timeout=%s", namespace, name, timeoutArg)
	if out, err := config.Server.RunKubectl(cmd); err != nil {
		return fmt.Errorf("deployment %s/%s did not become ready: %s: %w", namespace, name, out, err)
	}
	return nil
}

func (config *TestConfig) WaitForDaemonSetReady(namespace, name string, timeout time.Duration) error {
	timeoutArg := fmt.Sprintf("%ds", int(timeout.Seconds()))
	cmd := fmt.Sprintf("-n %s rollout status daemonset/%s --timeout=%s", namespace, name, timeoutArg)
	if out, err := config.Server.RunKubectl(cmd); err != nil {
		return fmt.Errorf("daemonset %s/%s did not become ready: %s: %w", namespace, name, out, err)
	}
	return nil
}

func (config *TestConfig) EnsureScannerNamespace() error {
	cmd := fmt.Sprintf("create namespace %s", scannerNamespace)
	if out, err := config.Server.RunKubectl(cmd); err != nil {
		return fmt.Errorf("failed to ensure scanner namespace: %s: %w", out, err)
	}
	return nil
}

func (config *TestConfig) RunImageCVE(component string) (string, error) {

	if err := config.CopyPatcherBinaryToServer(); err != nil {
		return "", err
	}

	command := fmt.Sprintf(
		"KUBECONFIG=/etc/rancher/rke2/rke2.yaml %s image-cve %s",
		nodePatcherBinaryPath,
		component,
	)

	out, err := config.Server.RunCmdOnNode(command)
	if err != nil {
		return out, fmt.Errorf("image-cve failed for %s: %w", component, err)
	}
	return out, nil
}

func (config *TestConfig) RunImageList(component string, withCVEs bool) (string, error) {
	if err := config.CopyPatcherBinaryToServer(); err != nil {
		return "", err
	}

	args := []string{"image-list"}
	if withCVEs {
		args = append(args, "--with-cves")
	}
	args = append(args, component)
	command := fmt.Sprintf(
		"KUBECONFIG=/etc/rancher/rke2/rke2.yaml %s %s",
		nodePatcherBinaryPath,
		strings.Join(args, " "),
	)

	out, err := config.Server.RunCmdOnNode(command)
	if err != nil {
		return out, fmt.Errorf("image-list failed for %s: %w", component, err)
	}
	return out, nil
}

func (config *TestConfig) RunImagePatch(component string, dryRun bool) (string, error) {
	if err := config.CopyPatcherBinaryToServer(); err != nil {
		return "", err
	}

	args := []string{"image-patch"}
	if dryRun {
		args = append(args, "--dry-run")
	}
	args = append(args, "--yes")
	args = append(args, component)
	command := fmt.Sprintf(
		"KUBECONFIG=/etc/rancher/rke2/rke2.yaml %s %s",
		nodePatcherBinaryPath,
		strings.Join(args, " "),
	)

	out, err := config.Server.RunCmdOnNode(command)
	if err != nil {
		return out, fmt.Errorf("image-patch failed for %s: %w", component, err)
	}
	return out, nil
}

func (config *TestConfig) RunImageReconcile(component string, dryRun bool) (string, error) {
	if err := config.CopyPatcherBinaryToServer(); err != nil {
		return "", err
	}

	args := []string{"image-reconcile"}
	if dryRun {
		args = append(args, "--dry-run")
	}
	args = append(args, "--yes")
	args = append(args, component)
	command := fmt.Sprintf(
		"KUBECONFIG=/etc/rancher/rke2/rke2.yaml %s %s",
		nodePatcherBinaryPath,
		strings.Join(args, " "),
	)

	out, err := config.Server.RunCmdOnNode(command)
	if err != nil {
		return out, fmt.Errorf("image-reconcile failed for %s: %w", component, err)
	}
	return out, nil
}

// GetRunningImageTag returns the image tag for the container in workloadKind/workloadName
// whose image path contains the given repository substring.
func (config *TestConfig) GetRunningImageTag(namespace, workloadKind, workloadName, repository string) (string, error) {
	kubectlArgs := fmt.Sprintf("-n %s get %s/%s -o jsonpath='{range .spec.template.spec.containers[*]}{.image} {end}'", namespace, workloadKind, workloadName)
	out, err := config.Server.RunKubectl(kubectlArgs)
	if err != nil {
		return "", fmt.Errorf("failed to get images for %s/%s: %w", workloadKind, workloadName, err)
	}
	for _, img := range strings.Fields(out) {
		if strings.Contains(img, repository) {
			parts := strings.SplitN(img, ":", 2)
			if len(parts) == 2 {
				return parts[1], nil
			}
		}
	}
	return "", fmt.Errorf("no image matching repository %q found in %s/%s: output=%q", repository, workloadKind, workloadName, out)
}

func (config *TestConfig) DumpServiceLogs(lines int) string {
	if config.Server.Name == "" {
		return ""
	}
	cmd := fmt.Sprintf("journalctl -u rke2-server -n %d --no-pager", lines)
	out, err := config.Server.RunCmdOnNode(cmd)
	if err != nil {
		return fmt.Sprintf("failed to get server logs: %v", err)
	}
	return out
}

func (config *TestConfig) DumpResources() string {
	if config.Server.Name == "" {
		return ""
	}
	out, err := config.Server.RunKubectl("get pods,deploy,ds -A -o wide")
	if err != nil {
		return fmt.Sprintf("failed to dump cluster resources: %v", err)
	}
	return out
}

func (config *TestConfig) Cleanup() error {
	errs := make([]string, 0)

	if config.Server.Name != "" {
		if out, err := RunCommand("docker rm -f " + config.Server.Name); err != nil {
			errs = append(errs, fmt.Sprintf("cleanup server failed: %s: %v", out, err))
		}
	}

	if config.TestDir != "" {
		if err := os.RemoveAll(config.TestDir); err != nil {
			errs = append(errs, fmt.Sprintf("cleanup temp dir failed: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup failed: %s", strings.Join(errs, "; "))
	}

	return nil
}

func (config *TestConfig) waitForKubeconfig(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, err := config.Server.RunCmdOnNode("test -f /etc/rancher/rke2/rke2.yaml")
		if err == nil {
			return nil
		}
		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("timed out waiting for /etc/rancher/rke2/rke2.yaml")
}

func (config *TestConfig) waitForNodesReady(timeout time.Duration, expectedNodes int) error {
	deadline := time.Now().Add(timeout)
	var lastErr error

	for time.Now().Before(deadline) {
		lastErr = config.CheckNodesReady(expectedNodes)
		if lastErr == nil {
			return nil
		}
		time.Sleep(5 * time.Second)
	}

	if lastErr == nil {
		return fmt.Errorf("timed out waiting for nodes to be ready")
	}

	return fmt.Errorf("timed out waiting for nodes to be ready: %w", lastErr)
}

func (config *TestConfig) CopyAndModifyKubeconfig() error {
	kubeconfigPath := filepath.Join(config.TestDir, "kubeconfig.yaml")
	copyCmd := fmt.Sprintf("docker cp %s:/etc/rancher/rke2/rke2.yaml %s", config.Server.Name, kubeconfigPath)
	if out, err := RunCommand(copyCmd); err != nil {
		return fmt.Errorf("failed to copy kubeconfig: %s: %w", out, err)
	}

	sedCmd := fmt.Sprintf("sed -i -e \"s/:6443/:%d/g\" %s", config.Server.Port, kubeconfigPath)
	if out, err := RunCommand(sedCmd); err != nil {
		return fmt.Errorf("failed to rewrite kubeconfig server port: %s: %w", out, err)
	}

	config.KubeconfigFile = kubeconfigPath
	return nil
}

func (config *TestConfig) writeServerConfig(serverConfig string) error {
	b64Config := base64.StdEncoding.EncodeToString([]byte(serverConfig))
	cmd := fmt.Sprintf("mkdir -p /etc/rancher/rke2 && echo %s | base64 -d > /etc/rancher/rke2/config.yaml", b64Config)
	if out, err := config.Server.RunCmdOnNode(cmd); err != nil {
		return fmt.Errorf("failed to write server config: %s: %w", out, err)
	}
	return nil
}

func (config *TestConfig) CreateTraefikCorednsHelmChartConfig() error {

	corednsManifest := `---
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-coredns
  namespace: kube-system
spec:
  valuesContent: |-
    nodelocal:
      enabled: true
`
	traefikManifest := `---
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-traefik
  namespace: kube-system
spec:
  valuesContent: |-
    providers:
      kubernetesGateway:
        enabled: true
`
	manifests := []string{corednsManifest, traefikManifest}
	for _, manifest := range manifests {
		b64 := base64.StdEncoding.EncodeToString([]byte(manifest))
		cmd := "echo " + b64 + " | base64 -d | KUBECONFIG=/etc/rancher/rke2/rke2.yaml PATH=$PATH:/var/lib/rancher/rke2/bin kubectl apply -f -"
		if out, err := config.Server.RunCmdOnNode(cmd); err != nil {
			return fmt.Errorf("failed to apply manifest: %s: %w", out, err)
		}
	}
	return nil
}

func (node DockerNode) RunCmdOnNode(command string) (string, error) {
	cmd := fmt.Sprintf("docker exec %s /bin/sh -c \"%s\"", node.Name, command)
	out, err := RunCommand(cmd)
	if err != nil {
		return out, fmt.Errorf("%w: node=%s output=%s", err, node.Name, out)
	}
	return out, nil
}

func (node DockerNode) RunKubectl(kubectlArgs string) (string, error) {
	cmd := "KUBECONFIG=/etc/rancher/rke2/rke2.yaml PATH=$PATH:/var/lib/rancher/rke2/bin kubectl " + kubectlArgs
	return node.RunCmdOnNode(cmd)
}

func RunCommand(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("failed to run %q: %w", command, err)
	}
	return string(out), nil
}

func getPort() int {
	for i := 0; i < 100; i++ {
		port := 10000 + rand.Intn(50000)
		if portFree(port) {
			return port
		}
	}
	return -1
}

func portFree(port int) bool {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}
