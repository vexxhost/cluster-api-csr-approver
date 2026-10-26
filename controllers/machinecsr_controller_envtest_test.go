/*
Copyright 2026 VEXXHOST, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"net"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	"sigs.k8s.io/cluster-api/util/conditions"
	"sigs.k8s.io/cluster-api/util/kubeconfig"

	"github.com/vexxhost/cluster-api-csr-approver/pkg/csr"
	"github.com/vexxhost/cluster-api-csr-approver/pkg/csr/csrtest"
)

// envFixture is a Cluster with a reachable "workload cluster". Like the
// Cluster API test suites, the workload cluster is the envtest API server
// itself, reached through a <cluster>-kubeconfig Secret.
type envFixture struct {
	t         *testing.T
	g         *WithT
	ctx       context.Context
	namespace string
	cluster   *clusterv1.Cluster
	suffix    string
}

func newEnvFixture(t *testing.T, clusterLabels map[string]string) *envFixture {
	t.Helper()
	requireEnvtest(t)
	g := NewWithT(t)
	ctx := context.Background()
	suffix := rand.String(6)

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-" + suffix}}
	g.Expect(envClient.Create(ctx, ns)).To(Succeed())

	cluster := &clusterv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-" + suffix, Namespace: ns.Name, Labels: clusterLabels},
		Spec: clusterv1.ClusterSpec{
			InfrastructureRef: clusterv1.ContractVersionedObjectReference{
				APIGroup: "infrastructure.cluster.x-k8s.io",
				Kind:     "GenericInfrastructureCluster",
				Name:     "cluster-" + suffix,
			},
		},
	}
	g.Expect(envClient.Create(ctx, cluster)).To(Succeed())
	g.Expect(envClient.Create(ctx, kubeconfig.GenerateSecret(cluster, kubeconfig.FromEnvTestConfig(envConfig, cluster)))).To(Succeed())

	f := &envFixture{t: t, g: g, ctx: ctx, namespace: ns.Name, cluster: cluster, suffix: suffix}
	f.setClusterReady()
	return f
}

func (f *envFixture) setClusterReady() {
	f.t.Helper()
	f.cluster.Status.Initialization.InfrastructureProvisioned = ptr.To(true)
	conditions.Set(f.cluster, metav1.Condition{
		Type:   clusterv1.ClusterControlPlaneInitializedCondition,
		Status: metav1.ConditionTrue,
		Reason: clusterv1.ClusterControlPlaneInitializedReason,
	})
	f.g.Expect(envClient.Status().Update(f.ctx, f.cluster)).To(Succeed())
}

// nodeName returns a node name that is unique across tests, since every
// fixture shares the same envtest API server as its workload cluster.
func (f *envFixture) nodeName(name string) string {
	return name + "-" + f.suffix
}

func (f *envFixture) createMachine(name, nodeName string, addresses clusterv1.MachineAddresses) *clusterv1.Machine {
	f.t.Helper()
	m := &clusterv1.Machine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: f.namespace,
			Labels:    map[string]string{clusterv1.ClusterNameLabel: f.cluster.Name},
		},
		Spec: clusterv1.MachineSpec{
			ClusterName: f.cluster.Name,
			Bootstrap:   clusterv1.Bootstrap{DataSecretName: ptr.To("bootstrap")},
			InfrastructureRef: clusterv1.ContractVersionedObjectReference{
				APIGroup: "infrastructure.cluster.x-k8s.io",
				Kind:     "GenericInfrastructureMachine",
				Name:     name,
			},
		},
	}
	f.g.Expect(envClient.Create(f.ctx, m)).To(Succeed())

	m.Status.Addresses = addresses
	if nodeName != "" {
		m.Status.NodeRef = clusterv1.MachineNodeReference{Name: nodeName}
	}
	f.g.Expect(envClient.Status().Update(f.ctx, m)).To(Succeed())
	return m
}

func (f *envFixture) updateMachineStatus(m *clusterv1.Machine, mutate func(m *clusterv1.Machine)) {
	f.t.Helper()
	f.g.Eventually(func() error {
		if err := envClient.Get(f.ctx, client.ObjectKeyFromObject(m), m); err != nil {
			return err
		}
		mutate(m)
		return envClient.Status().Update(f.ctx, m)
	}, eventually...).Should(Succeed())
}

// createNodeCSR creates a kubelet serving CSR authenticated as nodeName, the
// way the kubelet does after TLS bootstrapping.
func (f *envFixture) createNodeCSR(nodeName string, req csrtest.Request) string {
	f.t.Helper()
	cfg := rest.CopyConfig(envConfig)
	cfg.Impersonate = rest.ImpersonationConfig{
		UserName: csr.NodeUserPrefix + nodeName,
		Groups:   []string{csr.NodesGroup, "system:authenticated"},
	}
	nodeClient, err := client.New(cfg, client.Options{Scheme: envScheme})
	f.g.Expect(err).ToNot(HaveOccurred())

	c := csrtest.KubeletServing("", nodeName, req)
	c.GenerateName = "csr-"
	c.Spec.Username = ""
	c.Spec.Groups = nil
	f.g.Expect(nodeClient.Create(f.ctx, c)).To(Succeed())
	f.t.Cleanup(func() { _ = envClient.Delete(context.Background(), c) })
	return c.Name
}

func (f *envFixture) csrState(name string) func() string {
	return func() string {
		c := &certificatesv1.CertificateSigningRequest{}
		if err := envClient.Get(f.ctx, client.ObjectKey{Name: name}, c); err != nil {
			return "error: " + err.Error()
		}
		for _, cond := range c.Status.Conditions {
			if cond.Status != corev1.ConditionTrue {
				continue
			}
			switch cond.Type {
			case certificatesv1.CertificateApproved:
				return "Approved/" + cond.Reason
			case certificatesv1.CertificateDenied:
				return "Denied/" + cond.Reason
			}
		}
		return "Pending"
	}
}

func (f *envFixture) machineEvents(m *clusterv1.Machine) func() []string {
	return func() []string {
		events := &corev1.EventList{}
		if err := envClient.List(f.ctx, events, client.InNamespace(f.namespace)); err != nil {
			return []string{"error: " + err.Error()}
		}
		var out []string
		for _, e := range events.Items {
			if e.InvolvedObject.Kind == "Machine" && e.InvolvedObject.Name == m.Name {
				out = append(out, strings.Join([]string{e.Type, e.Reason, e.Message}, " "))
			}
		}
		return out
	}
}

func addressesFor(nodeName string, ips ...string) clusterv1.MachineAddresses {
	addrs := clusterv1.MachineAddresses{{Type: clusterv1.MachineHostName, Address: nodeName}}
	for _, ip := range ips {
		addrs = append(addrs, clusterv1.MachineAddress{Type: clusterv1.MachineInternalIP, Address: ip})
	}
	return addrs
}

func servingRequest(nodeName string, ips ...string) csrtest.Request {
	r := csrtest.Request{DNSNames: []string{nodeName}}
	for _, ip := range ips {
		r.IPAddresses = append(r.IPAddresses, net.ParseIP(ip))
	}
	return r
}

const approvedState = "Approved/" + ApprovedReason

func TestEnvApprovesCSRMatchingMachineAddresses(t *testing.T) {
	f := newEnvFixture(t, nil)
	node := f.nodeName("cp-0")
	m := f.createMachine("cp-0", node, addressesFor(node, "10.0.0.10", "fd00::10"))

	name := f.createNodeCSR(node, servingRequest(node, "10.0.0.10", "fd00::10"))

	f.g.Eventually(f.csrState(name), eventually...).Should(Equal(approvedState))
	f.g.Eventually(f.machineEvents(m), eventually...).Should(ContainElement(
		ContainSubstring("Normal CSRApproved Approved kubelet serving CertificateSigningRequest " + name)))
}

func TestEnvApprovesCSRCreatedBeforeNodeIsLinked(t *testing.T) {
	f := newEnvFixture(t, nil)
	node := f.nodeName("worker-0")
	m := f.createMachine("worker-0", "", addressesFor(node, "10.0.0.20"))

	name := f.createNodeCSR(node, servingRequest(node, "10.0.0.20"))
	f.g.Consistently(f.csrState(name), consistently...).Should(Equal("Pending"))

	// Cluster API links the Node to the Machine shortly after the kubelet registers.
	f.updateMachineStatus(m, func(m *clusterv1.Machine) {
		m.Status.NodeRef = clusterv1.MachineNodeReference{Name: node}
	})
	f.g.Eventually(f.csrState(name), eventually...).Should(Equal(approvedState))
}

func TestEnvLeavesCSRForForeignIPPending(t *testing.T) {
	f := newEnvFixture(t, nil)
	victim := f.nodeName("worker-a")
	attacker := f.nodeName("worker-b")
	f.createMachine("worker-a", victim, addressesFor(victim, "10.0.0.30"))
	m := f.createMachine("worker-b", attacker, addressesFor(attacker, "10.0.0.31"))

	// worker-b asks for a certificate that is also valid for worker-a's IP.
	name := f.createNodeCSR(attacker, servingRequest(attacker, "10.0.0.31", "10.0.0.30"))

	f.g.Eventually(f.machineEvents(m), eventually...).Should(ContainElement(SatisfyAll(
		ContainSubstring("Warning CSRNotApproved"),
		ContainSubstring(name),
		ContainSubstring(`IP address "10.0.0.30" is not an address of the Machine`),
	)))
	f.g.Consistently(f.csrState(name), consistently...).Should(Equal("Pending"))
}

func TestEnvLeavesCSRForAnotherNodesNamePending(t *testing.T) {
	f := newEnvFixture(t, nil)
	victim := f.nodeName("worker-a")
	attacker := f.nodeName("worker-b")
	f.createMachine("worker-a", victim, addressesFor(victim, "10.0.0.40"))
	f.createMachine("worker-b", attacker, addressesFor(attacker, "10.0.0.41"))

	name := f.createNodeCSR(attacker, csrtest.Request{
		DNSNames:    []string{attacker, victim},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.41")},
	})

	f.g.Consistently(f.csrState(name), consistently...).Should(Equal("Pending"))
}

func TestEnvApprovesOnceMachineReportsNewAddress(t *testing.T) {
	f := newEnvFixture(t, nil)
	node := f.nodeName("worker-0")
	m := f.createMachine("worker-0", node, addressesFor(node, "10.0.0.50"))

	// The kubelet already sees a floating IP the provider has not reported yet.
	name := f.createNodeCSR(node, servingRequest(node, "10.0.0.50", "203.0.113.50"))
	f.g.Consistently(f.csrState(name), consistently...).Should(Equal("Pending"))

	f.updateMachineStatus(m, func(m *clusterv1.Machine) {
		m.Status.Addresses = append(m.Status.Addresses, clusterv1.MachineAddress{Type: clusterv1.MachineExternalIP, Address: "203.0.113.50"})
	})
	f.g.Eventually(f.csrState(name), eventually...).Should(Equal(approvedState))
}

func TestEnvSkipsClustersOutsideTheSelector(t *testing.T) {
	f := newEnvFixture(t, map[string]string{skipLabel: "true"})
	node := f.nodeName("worker-0")
	f.createMachine("worker-0", node, addressesFor(node, "10.0.0.60"))

	name := f.createNodeCSR(node, servingRequest(node, "10.0.0.60"))

	f.g.Consistently(f.csrState(name), consistently...).Should(Equal("Pending"))
}

func TestEnvWaitsForPausedClusters(t *testing.T) {
	f := newEnvFixture(t, nil)
	f.g.Eventually(func() error {
		if err := envClient.Get(f.ctx, client.ObjectKeyFromObject(f.cluster), f.cluster); err != nil {
			return err
		}
		f.cluster.Spec.Paused = ptr.To(true)
		return envClient.Update(f.ctx, f.cluster)
	}, eventually...).Should(Succeed())

	node := f.nodeName("worker-0")
	f.createMachine("worker-0", node, addressesFor(node, "10.0.0.70"))
	name := f.createNodeCSR(node, servingRequest(node, "10.0.0.70"))
	f.g.Consistently(f.csrState(name), consistently...).Should(Equal("Pending"))

	f.g.Eventually(func() error {
		if err := envClient.Get(f.ctx, client.ObjectKeyFromObject(f.cluster), f.cluster); err != nil {
			return err
		}
		f.cluster.Spec.Paused = nil
		return envClient.Update(f.ctx, f.cluster)
	}, eventually...).Should(Succeed())
	f.g.Eventually(f.csrState(name), eventually...).Should(Equal(approvedState))
}

func TestEnvIgnoresCSRsForOtherSigners(t *testing.T) {
	f := newEnvFixture(t, nil)
	node := f.nodeName("worker-0")
	f.createMachine("worker-0", node, addressesFor(node, "10.0.0.80"))

	cfg := rest.CopyConfig(envConfig)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: csr.NodeUserPrefix + node, Groups: []string{csr.NodesGroup, "system:authenticated"}}
	nodeClient, err := client.New(cfg, client.Options{Scheme: envScheme})
	f.g.Expect(err).ToNot(HaveOccurred())

	c := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "csr-client-"},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    csrtest.MustPEM(node, csrtest.Request{}),
			SignerName: certificatesv1.KubeAPIServerClientKubeletSignerName,
			Usages:     []certificatesv1.KeyUsage{certificatesv1.UsageDigitalSignature, certificatesv1.UsageClientAuth},
		},
	}
	f.g.Expect(nodeClient.Create(f.ctx, c)).To(Succeed())
	t.Cleanup(func() { _ = envClient.Delete(context.Background(), c) })

	// A serving CSR from the same node proves the controller is active for it.
	serving := f.createNodeCSR(node, servingRequest(node, "10.0.0.80"))
	f.g.Eventually(f.csrState(serving), eventually...).Should(Equal(approvedState))
	f.g.Consistently(f.csrState(c.Name), consistently...).Should(Equal("Pending"))
}

func TestEnvApprovesCSRsAcrossManyMachines(t *testing.T) {
	f := newEnvFixture(t, nil)

	var names []string
	for i := range 5 {
		node := f.nodeName("worker-" + string(rune('a'+i)))
		ip := "10.0.1." + string(rune('0'+i+1))
		f.createMachine("worker-"+string(rune('a'+i)), node, addressesFor(node, ip))
		names = append(names, f.createNodeCSR(node, servingRequest(node, ip)))
	}

	for _, name := range names {
		f.g.Eventually(f.csrState(name), eventually...).Should(Equal(approvedState))
	}
}
