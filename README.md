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
rke2-patcher --config
rke2-patcher image-cve <component>
rke2-patcher image-list <component> [--with-cves] [--verbose]
rke2-patcher image-patch <component> [--dry-run]
rke2-patcher image-reconcile <component>
```

- `--version` always prints the CLI version and also tries to print the connected cluster version (`gitVersion`) from Kubernetes API `/version`.
- If Kubernetes access is not available, `--version` still succeeds and reports cluster version as unavailable.

Make targets:

```bash
make version
make image-cve COMPONENT=rke2-traefik
make image-list COMPONENT=rke2-traefik
make image-patch COMPONENT=rke2-traefik
make test-docker-default
make test-docker-calico-traefik
```

## Docker scenario tests (Ginkgo)

The repository includes Docker end-to-end scenario tests, modeled after the RKE2 Docker test style:

- Test locations:
  - `tests/docker/default_components/default_components_test.go`
  - `tests/docker/calico_traefik/calico_traefik_test.go`
- Shared harness: `tests/docker/testutils.go`
- CI workflow: `.github/workflows/docker-tests.yaml`

What this first scenario does:

1. Deploys an RKE2 server in Docker with `v1.35.3+rke2r3` and standard configuration.
2. Waits for the default core components to become ready.
3. Runs `rke2-patcher image-cve` and verifies CVEs are reported for:
  - `rke2-coredns`
  - `rke2-coredns-cluster-autoscaler`
  - `rke2-canal-flannel`
  - `rke2-ingress-nginx`
  - `rke2-metrics-server`
  - `rke2-snapshot-controller`

  What the second scenario does:

  1. Deploys an RKE2 server in Docker with `v1.35.3+rke2r3` and config:
    - `cni: calico`
    - `ingress-controller: traefik`
  2. Runs:
    - `image-list rke2-traefik`
    - `image-list --with-cves rke2-calico-operator`
  3. Verifies both commands return expected listing output.

Run locally:

```bash
make test-docker-default
make test-docker-calico-traefik
```

Or directly:

```bash
go build -o ./bin/rke2-patcher .
go test -v -timeout=80m ./tests/docker/default_components/default_components_test.go -ginkgo.v -rke2Version v1.35.3+rke2r3 -patcherBin ./bin/rke2-patcher
go test -v -timeout=80m ./tests/docker/calico_traefik/calico_traefik_test.go -ginkgo.v -rke2Version v1.35.3+rke2r3 -patcherBin ./bin/rke2-patcher
```

### 0) Show effective configuration

```bash
rke2-patcher --config
```

- Prints effective/default/source for relevant runtime config values.
- Includes registry, scanner mode, scanner image, scanner namespace, timeout, manifests path, and RKE2 patcher state ConfigMap coordinates.

### 1) CVEs of current running image

```bash
rke2-patcher image-cve rke2-traefik
```

- Looks up the current running image in the cluster for the selected component.
- Scans it for CVEs using an in-cluster Kubernetes `Job` that runs `trivy`.
- Uses cluster mode by default (`RKE2_PATCHER_CVE_MODE=cluster`).
- In cluster mode, if the target scan namespace does not exist, the tool asks whether it should create it and creates it on confirmation.
- In local mode (`RKE2_PATCHER_CVE_MODE=local`), it tries local scanners in order: `trivy` first, then `grype` as fallback.
- `grype` support is experimental.
- In local mode, both `trivy` and `grype` use a shared local VEX file at `$HOME/rke2-patcher-cache/vex/rancher.openvex.json`:
  - if the file exists and is newer than 24 hours, it is reused (no download)
  - if the file exists but is older than 24 hours, a refresh is attempted (up to 3 tries); on failure, the stale local file is still used
  - if the file does not exist, download is attempted (up to 3 tries); if all fail, local scan errors

### 2) List available images (tags)

```bash
rke2-patcher image-list rke2-traefik
```

```bash
rke2-patcher image-list rke2-traefik --with-cves
```

```bash
rke2-patcher image-list rke2-traefik --with-cves --verbose
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
rke2-patcher image-patch rke2-traefik
```

```bash
rke2-patcher image-patch rke2-traefik --dry-run
```

- Detects the current running image repository in-cluster.
- Picks the next newer tag from `registry.rancher.com` and writes a `HelmChartConfig` manifest with that tag.
- With `--dry-run`, prints the exact `HelmChartConfig` that would be written and does not write any file.
- Refuses to patch when current tag is already the newest available tag.
- Refuses to patch when the target tag would move to a newer minor release.
- Refuses to patch when the same component was already patched forward once for the current detected RKE2 version.
- Refuses to patch when any stale patch state from a different RKE2 version still exists. In that case, run `rke2-patcher image-reconcile <component>` for each previously patched component before patching again.
- Refuses to write if the target manifests directory does not exist and suggests setting `RKE2_PATCHER_DATA_DIR`.
- If one or more `HelmChartConfig` objects already exist in the cluster for the same chart name and namespace, asks for confirmation before attempting a merge.
- If merge is approved, prints the merged output in dry-run format and asks for a second confirmation before writing.
- Generated image/repository lines are marked with `# change made by rke2-patcher` so patcher-managed overrides are easy to identify during review.
- For `rke2-canal-calico`, it updates the chart values under `calico.cniImage`, `calico.nodeImage`, `calico.flexvolImage`, and `calico.kubeControllerImage`.
- For `rke2-canal-flannel`, it updates the chart values under `flannel.image.repository` and `flannel.image.tag`.
- For `rke2-calico-operator`, it updates `tigeraOperator.image`, `tigeraOperator.version`, and `tigeraOperator.registry`.
- For `rke2-cilium-operator`, it updates `operator.image.repository` and `operator.image.tag`.
- For `rke2-ingress-nginx`, it updates `controller.image.repository` and `controller.image.tag`.

### 4) Reconcile one component (stale cleanup or patch revert)

```bash
rke2-patcher image-reconcile rke2-traefik
```

- `image-reconcile` requires a single `<component>` argument.
- It only touches the `HelmChartConfig` file previously managed for that component.
- It first acts on state entries recorded for a different RKE2 version than the one currently running.
- If no stale entries are found but a same-version patch exists for the component, it asks whether to revert that patch.
- On approval, it removes only the patcher-managed image override keys from `valuesContent`, then writes the file back in place.
- It does not delete the `HelmChartConfig` file; the file update lets RKE2 re-render the chart using bundled defaults.
- After the file is updated successfully, the corresponding processed state entry for that component is removed.
- If multiple components were patched before the upgrade, run `image-reconcile <component>` once for each of them.

Typical upgrade flow:

1. Patch one or more components with `image-patch`.
2. Upgrade RKE2.
3. Run `rke2-patcher image-reconcile <component>` for each patched component.
4. Once stale entries are cleared, `image-patch` is allowed again.

## Supported components

- `rke2-traefik` -> `rancher/hardened-traefik`
- `rke2-ingress-nginx` -> `rancher/nginx-ingress-controller`
- `rke2-coredns` -> `rancher/hardened-coredns`
- `rke2-dns-node-cache` -> `rancher/hardened-dns-node-cache`
- `rke2-calico-operator` -> `rancher/mirrored-calico-operator`
- `rke2-cilium-operator` -> `rancher/mirrored-cilium-operator-generic`
- `rke2-metrics-server` -> `rancher/hardened-k8s-metrics-server`
- `rke2-flannel` -> `rancher/hardened-flannel`
- `rke2-canal-calico` -> `rancher/hardened-calico`
- `rke2-canal-flannel` -> `rancher/hardened-flannel`
- `rke2-coredns-cluster-autoscaler` -> `rancher/hardened-cluster-autoscaler`
- `rke2-snapshot-controller` -> `rancher/hardened-snapshot-controller`

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
- For `image-patch`, Kubernetes access that allows reading/writing ConfigMaps in the state namespace (same namespace used by `RKE2_PATCHER_CVE_NAMESPACE`; default `rke2-patcher`).
- For `image-reconcile`, access to the same patcher state ConfigMap is required, and the generated `HelmChartConfig` file must still be writable in the manifests directory.
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

- Generated `HelmChartConfig` namespace
  - Hardcoded: `kube-system`

The `image-cve` command supports these overrides:

- `RKE2_PATCHER_CVE_MODE`
  - CVE scanner execution mode.
  - Allowed: `cluster`, `local`
  - Default: `cluster`
  - `cluster`: only in-cluster Trivy Job.
  - `local`: only local scanners.

- `RKE2_PATCHER_CVE_NAMESPACE`
  - Namespace where scan Jobs are created in cluster mode.
  - Also used as namespace for RKE2 patcher state storage.
  - Default: `rke2-patcher`

Patch-limit state storage (not configurable):

- Backend: Kubernetes `ConfigMap`
- Name: `rke2-patcher-state`
- Data key: `patch-limit-state.json`
- Namespace: `RKE2_PATCHER_CVE_NAMESPACE` (default `rke2-patcher`)

- `RKE2_PATCHER_CVE_SCANNER_IMAGE`
  - Scanner image used by cluster mode.
  - Default: `aquasec/trivy:0.69.3`

- `RKE2_PATCHER_CVE_JOB_TIMEOUT`
  - Timeout for waiting on scan Job completion.
  - Default: `8m`

Example:

```bash
RKE2_PATCHER_DATA_DIR=/var/lib/rancher/rke2 \
./rke2-patcher image-patch rke2-traefik
```
