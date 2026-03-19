# rke2-patcher

`rke2-patcher` is a small CLI to inspect and patch RKE2 component images.

## Build

```bash
go build -o rke2-patcher .
```

Or with Make:

```bash
make build
```

## Commands

```bash
rke2-patcher --version
rke2-patcher image-cve <component>
rke2-patcher image-list <component> [--with-cves] [--verbose]
rke2-patcher image-patch <component> [--dry-run] [--revert]
```

- `--version` always prints the CLI version and also tries to print the connected cluster version (`gitVersion`) from Kubernetes API `/version`.
- If Kubernetes access is not available, `--version` still succeeds and reports cluster version as unavailable.

Make targets:

```bash
make version
make image-cve COMPONENT=traefik
make image-list COMPONENT=traefik
make image-patch COMPONENT=traefik
```

### 1) CVEs of current running image

```bash
rke2-patcher image-cve traefik
```

- Looks up the current running image in the cluster for the selected component.
- Verifies the component workload exists in `kube-system` (DaemonSet/Deployment mapping).
- Scans it for CVEs using an in-cluster Kubernetes `Job` that runs `trivy`.
- Uses cluster mode by default (`RKE2_PATCHER_CVE_MODE=cluster`).
- In cluster mode, if the target scan namespace does not exist, the tool asks whether it should create it and creates it on confirmation.

### 2) List available images (tags)

```bash
rke2-patcher image-list traefik
```

```bash
rke2-patcher image-list traefik --with-cves
```

```bash
rke2-patcher image-list traefik --with-cves --verbose
```

- Lists release tags from the configured registry for the selected component repository, ordered newest-first (higher build date first), with current and previous tags included.
- Filters out non-release signature/attestation tags (for example `sha256-...*.sig` and `sha256-...*.att`) from `image-list` output.
- Highlights tags currently in use by running pods as `"<-- in use"` when cluster access is available.
- With `--with-cves`, prints a compact table with columns: `TAG`, `STATUS`, `CVE COUNT`, and `VULNERABILITIES`.
- CVEs are collected for: the current image tag, the previous image tag, and all newer available tags.
- `--with-cves` runs a single in-cluster Trivy job that scans all selected images.
- If that batch cluster scan fails, the command fails (no per-image fallback path).
- By default, the vulnerability list is truncated for readability.
- Use `--verbose` with `--with-cves` to show the full vulnerability list.

### 3) Patch to next image

```bash
rke2-patcher image-patch traefik
```

```bash
rke2-patcher image-patch traefik --dry-run
```

```bash
rke2-patcher image-patch traefik --revert
```

- Detects the current running image repository in-cluster.
- Verifies the component workload exists in `kube-system` (DaemonSet/Deployment mapping).
- Picks the next newer tag from `registry.rancher.com` and writes a `HelmChartConfig` manifest with that tag.
- With `--dry-run`, prints the exact `HelmChartConfig` that would be written and does not write any file.
- With `--revert`, moves one image back (to the previous/older tag).
- Refuses to patch when current tag is already the newest available tag.
- Refuses to patch when the target tag would move to a newer minor release.
- Refuses to patch when the same component was already patched forward once for the current detected RKE2 version.
- Refuses to revert when current tag is already the oldest available tag in the observed list.
- Refuses to write if the target manifests directory does not exist and suggests setting `RKE2_PATCHER_DATA_DIR`.
- If one or more `HelmChartConfig` objects already exist in the cluster for the same chart name and namespace, asks for confirmation before attempting a merge.
- If merge is approved, prints the merged output in dry-run format and asks for a second confirmation before writing.
- For `canal-calico`, it updates the chart values under `calico.cniImage`, `calico.nodeImage`, `calico.flexvolImage`, and `calico.kubeControllerImage`.
- For `canal-flannel`, it updates the chart values under `flannel.image.repository` and `flannel.image.tag`.
- For `calico-operator`, it updates `tigeraOperator.image`, `tigeraOperator.version`, and `tigeraOperator.registry`.
- For `cilium-operator`, it updates `operator.image.repository` and `operator.image.tag`.
- For `ingress-nginx`, it updates `controller.image.repository` and `controller.image.tag`.

## Supported components

- `traefik` -> `rancher/hardened-traefik`
- `ingress-nginx` -> `rancher/nginx-ingress-controller`
- `coredns` -> `rancher/hardened-coredns`
- `dns-node-cache` -> `rancher/hardened-dns-node-cache`
- `calico-operator` -> `rancher/mirrored-calico-operator`
- `cilium-operator` -> `rancher/mirrored-cilium-operator-generic`
- `metrics-server` -> `rancher/hardened-k8s-metrics-server`
- `flannel` -> `rancher/hardened-flannel`
- `canal-calico` -> `rancher/hardened-calico`
- `canal-flannel` -> `rancher/hardened-flannel`
- `csi-snapshotter` -> `rancher/hardened-csi-snapshotter`
- `coredns-cluster-autoscaler` -> `rancher/hardened-cluster-autoscaler`
- `snapshot-controller` -> `rancher/hardened-snapshot-controller`

## Requirements

- Kubernetes API access for `image-cve`, `image-patch`, and cluster-version detection in `--version`, using one of:
  - In-cluster service account files:
    - `/var/run/secrets/kubernetes.io/serviceaccount/token`
    - `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`
  - Kubeconfig (host binary mode on control-plane):
    - `KUBECONFIG` (first file in list), or
    - `/etc/rancher/rke2/rke2.yaml`, or
    - `~/.kube/config`
- Network access to the configured image registry endpoint (`RKE2_PATCHER_REGISTRY`, default `registry.rancher.com`).
- For `image-cve` default mode (`RKE2_PATCHER_CVE_MODE=cluster`), Kubernetes access that allows creating and reading Jobs/Pods in the scan namespace.
- Local scanner installation is optional and only needed when using local mode (`RKE2_PATCHER_CVE_MODE=local`):
  - `trivy`, or
  - `grype`

## Environment variables

General tag-registry override:

- `RKE2_PATCHER_REGISTRY`
  - Registry endpoint used to list available tags for `image-list` and `image-patch`.
  - Also used by `image-patch` when generating `calico-operator` values (`tigeraOperator.registry`).
  - Default: `registry.rancher.com`
  - Accepted forms: `registry.example.local`, `registry.example.local:5000`, `https://registry.example.local`, `http://registry.example.local:5000`
  - Behavior: tag listing starts unauthenticated, then follows Bearer challenge flow only if the registry returns `401` with `WWW-Authenticate: Bearer ...`.
  - To use Docker Hub instead: `RKE2_PATCHER_REGISTRY=registry-1.docker.io` (all Rancher component images are mirrored there publicly).

The `image-patch` command supports these overrides:

- `KUBECONFIG`
  - Optional kubeconfig path used when service account auth is not available.
  - If multiple files are provided, the first entry is used.
  - Useful when running as a host binary on control-plane nodes.

- `RKE2_PATCHER_DATA_DIR`
  - RKE2 data directory used to derive the manifest output path.
  - Default: `/var/lib/rancher/rke2`
  - Effective manifests path: `<data-dir>/server/manifests`
- `RKE2_PATCHER_CACHE_DIR`
  - Optional directory used to persist patch-limit state (one forward patch per component per RKE2 version).
  - Default state file path: `<data-dir>/server/rke2-patcher-cache/patch-limit-state.json`
- `RKE2_PATCHER_HELM_NAMESPACE`
  - `.metadata.namespace` for the generated `HelmChartConfig`.
  - Default: `kube-system`

The `image-cve` command supports these overrides:

- `RKE2_PATCHER_CVE_MODE`
  - CVE scanner execution mode.
  - Allowed: `cluster`, `local`
  - Default: `cluster`
  - `cluster`: only in-cluster Trivy Job.
  - `local`: only local scanners.

- `RKE2_PATCHER_CVE_NAMESPACE`
  - Namespace where the scan Job is created in cluster mode.
  - Default: `rke2-patcher`

- `RKE2_PATCHER_CVE_SCANNER_IMAGE`
  - Scanner image used by cluster mode.
  - Default: `aquasec/trivy:latest`

- `RKE2_PATCHER_CVE_JOB_TIMEOUT`
  - Timeout for waiting on scan Job completion.
  - Default: `8m`

Example:

```bash
RKE2_PATCHER_DATA_DIR=/var/lib/rancher/rke2 \
RKE2_PATCHER_HELM_NAMESPACE=kube-system \
./rke2-patcher image-patch traefik
```
