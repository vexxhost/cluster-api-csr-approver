//go:build e2e

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

package e2e

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	"sigs.k8s.io/cluster-api/test/framework"
	"sigs.k8s.io/cluster-api/util/secret"

	"github.com/vexxhost/cluster-api-csr-approver/controllers"
	"github.com/vexxhost/cluster-api-csr-approver/pkg/csr"
	"github.com/vexxhost/cluster-api-csr-approver/pkg/csr/csrtest"
)

const specName = "csr-approver"

// csrSpec holds the clients and helpers for checking one workload cluster.
type csrSpec struct {
	mgmt     framework.ClusterProxy
	workload framework.ClusterProxy
	cluster  *clusterv1.Cluster
}

func newCSRSpec(mgmt framework.ClusterProxy, namespace, clusterName string) *csrSpec {
	cluster := framework.GetClusterByName(ctx, framework.GetClusterByNameInput{
		Getter: mgmt.GetClient(), Name: clusterName, Namespace: namespace,
	})
	return &csrSpec{
		mgmt:     mgmt,
		workload: mgmt.GetWorkloadCluster(ctx, namespace, clusterName),
		cluster:  cluster,
	}
}

func (s *csrSpec) intervals(key string) []any {
	return e2eConfig.GetIntervals(specName, key)
}

// machinesByNode returns the Machines of the cluster keyed by node name.
func (s *csrSpec) machinesByNode() (map[string]*clusterv1.Machine, error) {
	machines := &clusterv1.MachineList{}
	if err := s.mgmt.GetClient().List(ctx, machines,
		client.InNamespace(s.cluster.Namespace),
		client.MatchingLabels{clusterv1.ClusterNameLabel: s.cluster.Name},
	); err != nil {
		return nil, err
	}
	out := map[string]*clusterv1.Machine{}
	for i := range machines.Items {
		m := &machines.Items[i]
		if m.Status.NodeRef.IsDefined() {
			out[m.Status.NodeRef.Name] = m
		}
	}
	return out, nil
}

// clusterCA returns the workload cluster CA from the <cluster>-ca Secret.
func (s *csrSpec) clusterCA() *x509.CertPool {
	caSecret, err := secret.GetFromNamespacedName(ctx, s.mgmt.GetClient(), client.ObjectKeyFromObject(s.cluster), secret.ClusterCA)
	Expect(err).ToNot(HaveOccurred())
	pool := x509.NewCertPool()
	Expect(pool.AppendCertsFromPEM(caSecret.Data[secret.TLSCrtDataName])).To(BeTrue(), "cluster CA should be valid PEM")
	return pool
}

// approvedCertificate returns the issued serving certificate for a node, or an
// error explaining why there is none yet.
func (s *csrSpec) approvedCertificate(node *corev1.Node) (*x509.Certificate, error) {
	csrs := &certificatesv1.CertificateSigningRequestList{}
	if err := s.workload.GetClient().List(ctx, csrs); err != nil {
		return nil, err
	}

	var states []string
	for i := range csrs.Items {
		c := &csrs.Items[i]
		if c.Spec.SignerName != certificatesv1.KubeletServingSignerName || c.Spec.Username != csr.NodeUserPrefix+node.Name {
			continue
		}
		approvedByUs := slices.ContainsFunc(c.Status.Conditions, func(cond certificatesv1.CertificateSigningRequestCondition) bool {
			return cond.Type == certificatesv1.CertificateApproved && cond.Status == corev1.ConditionTrue && cond.Reason == controllers.ApprovedReason
		})
		if !approvedByUs || len(c.Status.Certificate) == 0 {
			states = append(states, fmt.Sprintf("%s(approved=%t, issued=%t)", c.Name, approvedByUs, len(c.Status.Certificate) > 0))
			continue
		}
		block, _ := pem.Decode(c.Status.Certificate)
		if block == nil {
			return nil, fmt.Errorf("CSR %s has an invalid certificate", c.Name)
		}
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, fmt.Errorf("no approved and issued kubelet serving CSR for node %s yet, found %v", node.Name, states)
}

func (s *csrSpec) nodes() []corev1.Node {
	nodes := &corev1.NodeList{}
	Expect(s.workload.GetClient().List(ctx, nodes)).To(Succeed())
	return nodes.Items
}

// expectNodeApproved waits until node has an approved serving certificate that
// chains to the cluster CA and covers the node's addresses, and until the
// Machine records a CSRApproved event.
func (s *csrSpec) expectNodeApproved(node *corev1.Node, roots *x509.CertPool) {
	var cert *x509.Certificate
	Eventually(func() error {
		var err error
		cert, err = s.approvedCertificate(node)
		return err
	}, s.intervals("wait-csr-approved")...).Should(Succeed())

	_, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	Expect(err).ToNot(HaveOccurred(), "serving certificate of node %s should chain to the cluster CA", node.Name)
	Expect(cert.Subject.CommonName).To(Equal(csr.NodeUserPrefix + node.Name))
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			Expect(slices.ContainsFunc(cert.IPAddresses, net.ParseIP(addr.Address).Equal)).To(BeTrue(),
				"serving certificate of node %s should cover its InternalIP %s", node.Name, addr.Address)
		}
	}

	Eventually(func() ([]string, error) {
		machines, err := s.machinesByNode()
		if err != nil {
			return nil, err
		}
		m, ok := machines[node.Name]
		if !ok {
			return nil, fmt.Errorf("no Machine for node %s", node.Name)
		}
		return s.machineEvents(m), nil
	}, s.intervals("wait-csr-approved")...).Should(ContainElement(HavePrefix("Normal " + controllers.EventReasonApproved)))
}

func (s *csrSpec) machineEvents(m *clusterv1.Machine) []string {
	events := &corev1.EventList{}
	Expect(s.mgmt.GetClient().List(ctx, events, client.InNamespace(m.Namespace))).To(Succeed())
	var out []string
	for _, e := range events.Items {
		if e.InvolvedObject.Kind == "Machine" && e.InvolvedObject.Name == m.Name {
			out = append(out, strings.Join([]string{e.Type, e.Reason, e.Message}, " "))
		}
	}
	return out
}

func (s *csrSpec) expectAllNodesApproved(expectedNodes int) {
	roots := s.clusterCA()
	nodes := s.nodes()
	Expect(nodes).To(HaveLen(expectedNodes))
	for i := range nodes {
		Byf("Checking node %s", nodes[i].Name)
		s.expectNodeApproved(&nodes[i], roots)
	}
}

// expectLogsFromEveryNode reads container logs through kube-apiserver from a
// pod on every node. kube-apiserver runs with --kubelet-certificate-authority,
// so this only works when the kubelet serves a certificate signed by the
// cluster CA.
func (s *csrSpec) expectLogsFromEveryNode() {
	clientset := s.workload.GetClientSet()
	for _, node := range s.nodes() {
		Byf("Reading kube-proxy logs from node %s", node.Name)
		Eventually(func() error {
			pods := &corev1.PodList{}
			if err := s.workload.GetClient().List(ctx, pods,
				client.InNamespace("kube-system"),
				client.MatchingLabels{"k8s-app": "kube-proxy"},
			); err != nil {
				return err
			}
			for _, pod := range pods.Items {
				if pod.Spec.NodeName != node.Name {
					continue
				}
				_, err := clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{TailLines: ptr.To[int64](5)}).DoRaw(ctx)
				return err
			}
			return fmt.Errorf("no kube-proxy pod on node %s", node.Name)
		}, s.intervals("wait-kubelet-logs")...).Should(Succeed())
	}
}

// expectForgedCSRPending creates a serving CSR as a worker node that also asks
// for an IP the node does not own, and checks it is never approved.
func (s *csrSpec) expectForgedCSRPending() {
	machines, err := s.machinesByNode()
	Expect(err).ToNot(HaveOccurred())

	var node string
	for name, m := range machines {
		if _, isControlPlane := m.Labels[clusterv1.MachineControlPlaneLabel]; !isControlPlane {
			node = name
			break
		}
	}
	Expect(node).ToNot(BeEmpty(), "expected a worker node")

	cfg := rest.CopyConfig(s.workload.GetRESTConfig())
	cfg.Impersonate = rest.ImpersonationConfig{
		UserName: csr.NodeUserPrefix + node,
		Groups:   []string{csr.NodesGroup, "system:authenticated"},
	}
	nodeClient, err := client.New(cfg, client.Options{Scheme: s.workload.GetScheme()})
	Expect(err).ToNot(HaveOccurred())

	forged := csrtest.KubeletServing("", node, csrtest.Request{
		DNSNames:    []string{node},
		IPAddresses: []net.IP{net.ParseIP("203.0.113.99")},
	})
	forged.GenerateName = "forged-"
	forged.Spec.Username = ""
	forged.Spec.Groups = nil
	Expect(nodeClient.Create(ctx, forged)).To(Succeed())
	Byf("Created forged CertificateSigningRequest %s as node %s", forged.Name, node)

	Eventually(func() []string {
		return s.machineEvents(machines[node])
	}, s.intervals("wait-csr-approved")...).Should(ContainElement(SatisfyAll(
		HavePrefix("Warning "+controllers.EventReasonNotApproved),
		ContainSubstring(forged.Name),
		ContainSubstring(`IP address "203.0.113.99" is not an address of the Machine`),
	)))

	Consistently(func() ([]certificatesv1.CertificateSigningRequestCondition, error) {
		c := &certificatesv1.CertificateSigningRequest{}
		err := s.workload.GetClient().Get(ctx, client.ObjectKeyFromObject(forged), c)
		return c.Status.Conditions, err
	}, s.intervals("check-csr-pending")...).Should(BeEmpty(), "forged CSR %s must stay pending", forged.Name)

	Expect(s.workload.GetClient().Delete(ctx, forged)).To(Succeed())
}

// scaleWorkersAndExpectApproval scales the MachineDeployment and checks the
// new node gets an approved serving certificate.
func (s *csrSpec) scaleWorkersAndExpectApproval(replicas int32) {
	before := map[string]bool{}
	for _, n := range s.nodes() {
		before[n.Name] = true
	}

	mds := framework.GetMachineDeploymentsByCluster(ctx, framework.GetMachineDeploymentsByClusterInput{
		Lister: s.mgmt.GetClient(), ClusterName: s.cluster.Name, Namespace: s.cluster.Namespace,
	})
	Expect(mds).To(HaveLen(1))
	framework.ScaleAndWaitMachineDeployment(ctx, framework.ScaleAndWaitMachineDeploymentInput{
		ClusterProxy:              s.mgmt,
		Cluster:                   s.cluster,
		MachineDeployment:         mds[0],
		Replicas:                  replicas,
		WaitForMachineDeployments: e2eConfig.GetIntervals(specName, "wait-worker-nodes"),
	})

	var added []corev1.Node
	Eventually(func() error {
		added = nil
		for _, n := range s.nodes() {
			if !before[n.Name] {
				added = append(added, n)
			}
		}
		if len(added) == 0 {
			return errors.New("the new worker has not registered yet")
		}
		return nil
	}, s.intervals("wait-worker-nodes")...).Should(Succeed())

	roots := s.clusterCA()
	for i := range added {
		Byf("Checking new node %s", added[i].Name)
		s.expectNodeApproved(&added[i], roots)
	}
	s.expectLogsFromEveryNode()
}

// Byf is like By but with formatting.
func Byf(format string, a ...any) {
	By(fmt.Sprintf(format, a...))
}
