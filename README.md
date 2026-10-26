# cluster-api-csr-approver

`cluster-api-csr-approver` approves kubelet serving certificate requests in
[Cluster API](https://cluster-api.sigs.k8s.io/) workload clusters. It runs next
to Cluster API in the management cluster and approves a request only when every
DNS name and IP in it belongs to the Machine that backs the requesting Node.

It works with any infrastructure provider that reports Machine addresses
(CAPO, CAPD, CAPV, CAPZ, CAPA, Metal³ and so on). It doesn't require a
provider fork, and it doesn't install anything into workload clusters.

## Why

When kubelets run with `serverTLSBootstrap: true`, they request serving
certificates signed by the cluster CA through the `kubernetes.io/kubelet-serving`
signer. With `--kubelet-certificate-authority` set on kube-apiserver, the API
server then verifies the kubelet for `logs`, `exec`, `port-forward` and metrics,
instead of trusting a self-signed certificate.

Kubernetes deliberately [never auto-approves these requests][tls-bootstrap].
Something has to check that the requested names belong to the node. A node can
write its own `Node.status.addresses`, so those can't be trusted. The addresses
your infrastructure provider records on the Cluster API Machine can be.
OpenShift's [cluster-machine-approver][ocp-approver] and the [Cluster API
kubelet authentication proposal][capi-proposal] both use this design.

[tls-bootstrap]: https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/#certificate-rotation
[ocp-approver]: https://github.com/openshift/cluster-machine-approver
[capi-proposal]: https://github.com/kubernetes-sigs/cluster-api/blob/main/docs/proposals/20210222-kubelet-authentication.md

## How it works

The controller reconciles Cluster API Machines. For each Cluster it handles, it
uses the Cluster API `ClusterCache` to watch pending kubelet serving CSRs in the
workload cluster. It maps each CSR to its Machine through `status.nodeRef`, the
same way the Cluster API Machine controller maps Nodes. A CSR is approved when
all of these hold:

- The signer is `kubernetes.io/kubelet-serving`.
- It was requested by `system:node:<node>` in group `system:nodes`, and the
  Machine's `status.nodeRef.name` is `<node>`.
- The x509 subject is `CN=system:node:<node>, O=system:nodes`, and the request
  signature is valid.
- The usages are exactly those the signer allows: `server auth` and `digital
  signature`, plus `key encipherment` for RSA keys.
- There is at least one DNS or IP subjectAltName, and no email or URI SANs.
- Every IP is in `Machine.status.addresses`.
- Every DNS name is the node name or a `Hostname`, `InternalDNS` or
  `ExternalDNS` address of the Machine.
- If `--max-expiration` is set, `spec.expirationSeconds` doesn't exceed it.

Requests that fail are left pending by default, with a `CSRNotApproved` warning
event on the Machine explaining why, so other approvers or an administrator can
still act on them. With `--deny-invalid` they are denied instead. Certificate
renewals go through the same checks.

The controller skips Clusters that are paused, have no initialized control plane
yet, or don't match `--cluster-selector`. If a CSR arrives before Cluster API has
linked the Node to its Machine, or before the provider has reported an address,
the controller approves it as soon as the Machine is updated.

## Installing

Releases publish `addon-components.yaml` and `metadata.yaml`, so you can install
the controller as a clusterctl add-on provider. Add it to `clusterctl.yaml`:

```yaml
providers:
  - name: csr-approver
    type: AddonProvider
    url: https://github.com/vexxhost/cluster-api-csr-approver/releases/latest/addon-components.yaml
```

Then run:

```sh
clusterctl init --addon csr-approver
```

Without clusterctl, render the release manifest with
[`envsubst`](https://github.com/drone/envsubst) so the variable defaults below
are applied:

```sh
curl -sL https://github.com/vexxhost/cluster-api-csr-approver/releases/latest/download/addon-components.yaml \
  | envsubst | kubectl apply -f -
```

Images are published to `ghcr.io/vexxhost/cluster-api-csr-approver`.

### Configuration

| clusterctl variable | Flag | Default | Description |
|---|---|---|---|
| `CSR_APPROVER_CLUSTER_SELECTOR` | `--cluster-selector` | `csr-approver.vexxhost.com/disabled!=true` | Label selector for the Clusters to handle. The default handles every Cluster except those labeled `csr-approver.vexxhost.com/disabled=true`. Set it to e.g. `csr-approver.vexxhost.com/enabled=true` to make the controller opt-in. It doesn't connect to Clusters outside the selector. |
| `CSR_APPROVER_DENY_INVALID` | `--deny-invalid` | `false` | Deny failing requests instead of leaving them pending. |
| `CSR_APPROVER_MAX_EXPIRATION` | `--max-expiration` | `0s` (off) | Maximum lifetime a request may ask for through `spec.expirationSeconds`. |
| `CSR_APPROVER_DIAGNOSTICS_ADDRESS` | `--diagnostics-address` | `:8443` | Metrics and diagnostics endpoint, authenticated by default as in Cluster API. |
| `CSR_APPROVER_INSECURE_DIAGNOSTICS` | `--insecure-diagnostics` | `false` | Serve metrics over plain HTTP without authentication. |
| `CSR_APPROVER_LOG_LEVEL` | `--v` | `2` | Log verbosity. |

The usual Cluster API manager flags (`--watch-filter`, `--namespace`,
`--sync-period`, leader election, TLS and client QPS options) are also
available.

## Enabling kubelet serving certificates in a cluster

Set `serverTLSBootstrap: true` with a kubeadm `KubeletConfiguration` patch, as
described in the [Cluster API book][kubelet-config]. Then point kube-apiserver at
the cluster CA. For a `KubeadmControlPlane`:

```yaml
spec:
  kubeadmConfigSpec:
    clusterConfiguration:
      apiServer:
        extraArgs:
          - name: kubelet-certificate-authority
            value: /etc/kubernetes/pki/ca.crt
    initConfiguration:
      patches:
        directory: /etc/kubernetes/patches
    joinConfiguration:
      patches:
        directory: /etc/kubernetes/patches
    files:
      - path: /etc/kubernetes/patches/kubeletconfiguration0+strategic.json
        owner: root:root
        permissions: "0644"
        content: |
          {"apiVersion": "kubelet.config.k8s.io/v1beta1", "kind": "KubeletConfiguration", "serverTLSBootstrap": true}
```

Add the same file and `joinConfiguration.patches` to every
`KubeadmConfigTemplate`. A complete example is the [e2e cluster
template](test/e2e/data/infrastructure-docker/cluster-template.yaml).

Once `--kubelet-certificate-authority` is set, KubeadmControlPlane's etcd health
checks also go through the kubelet. Install the approver before you create
clusters that use this setting.

[kubelet-config]: https://cluster-api.sigs.k8s.io/tasks/bootstrap/kubeadm-bootstrap/kubelet-config

## Infrastructure provider requirements

The provider must report every IP and DNS name the kubelet puts in its serving
certificate in `Machine.status.addresses` (through the infrastructure machine's
`status.addresses`). The kubelet takes these from `Node.status.addresses`,
which the cloud controller manager fills in when one is used. If the node has an
address the Machine doesn't list, for example a floating IP the provider
doesn't report, the request stays pending. A `CSRNotApproved` event names the
missing address.

## Observability

- Events on the Machine: `CSRApproved`, `CSRNotApproved` and `CSRDenied`.
- Approved CSRs carry the reason `MachineAddressesVerified`, and denied ones
  carry `MachineAddressesMismatch`.
- The metric `capi_csr_approver_csr_total{result="approved|not_approved|denied"}`
  is exposed alongside the standard controller-runtime and Cluster API metrics.

## Using it as a library

`pkg/csr` contains the validation logic with no controller dependencies.
`controllers.MachineCSRReconciler` can be embedded in another manager. It needs
a Cluster API `ClusterCache` created with `controllers.ClusterCacheCacheOptions()`
and the `index.ByMachineNode` index on Machines.

## Development

```sh
make test      # unit tests and envtest integration tests (real kube-apiserver and ClusterCache)
make lint      # golangci-lint
make verify    # generated RBAC and go.mod are up to date
make test-e2e  # kind + CAPD end-to-end tests, requires Docker
```

The end-to-end suite uses the Cluster API test framework. It creates a kind
management cluster, installs Cluster API v1.14, CAPD and this controller as a
clusterctl add-on provider, and runs the Cluster API quick start with a cluster
whose kubelets request serving certificates. It checks that:

- every node gets a certificate signed by the cluster CA;
- kube-apiserver can read logs through every kubelet while verifying it;
- a forged request from a node asking for an IP it doesn't own stays pending;
- a worker added by scaling the MachineDeployment is approved too.

## License

Apache License 2.0. See [LICENSE](LICENSE).
