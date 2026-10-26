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
	"testing"

	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	"sigs.k8s.io/cluster-api/controllers/clustercache"
	"sigs.k8s.io/cluster-api/util/conditions"
	"sigs.k8s.io/cluster-api/util/index"

	"github.com/vexxhost/cluster-api-csr-approver/pkg/csr"
	"github.com/vexxhost/cluster-api-csr-approver/pkg/csr/csrtest"
)

const (
	testNamespace = "default"
	testCluster   = "test-cluster"
	testMachine   = "test-machine"
	testNode      = "test-node"
)

type unitTest struct {
	cluster    *clusterv1.Cluster
	machine    *clusterv1.Machine
	csrs       []*certificatesv1.CertificateSigningRequest
	reconciler func(r *MachineCSRReconciler)
	// disconnected simulates a workload cluster the ClusterCache cannot reach.
	disconnected bool
}

type unitResult struct {
	err      error
	csrs     map[string]*certificatesv1.CertificateSigningRequest
	events   []string
	recorder *record.FakeRecorder
}

func newCluster() *clusterv1.Cluster {
	cluster := &clusterv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{Name: testCluster, Namespace: testNamespace, Labels: map[string]string{}},
	}
	conditions.Set(cluster, metav1.Condition{
		Type:   clusterv1.ClusterControlPlaneInitializedCondition,
		Status: metav1.ConditionTrue,
		Reason: clusterv1.ClusterControlPlaneInitializedReason,
	})
	return cluster
}

func newMachine() *clusterv1.Machine {
	return &clusterv1.Machine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testMachine,
			Namespace: testNamespace,
			Labels:    map[string]string{clusterv1.ClusterNameLabel: testCluster},
		},
		Spec: clusterv1.MachineSpec{ClusterName: testCluster},
		Status: clusterv1.MachineStatus{
			NodeRef: clusterv1.MachineNodeReference{Name: testNode},
			Addresses: clusterv1.MachineAddresses{
				{Type: clusterv1.MachineHostName, Address: testNode},
				{Type: clusterv1.MachineInternalIP, Address: "10.0.0.10"},
			},
		},
	}
}

func validCSR(name string) *certificatesv1.CertificateSigningRequest {
	return csrtest.KubeletServing(name, testNode, csrtest.Request{
		DNSNames:    []string{testNode},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.10")},
	})
}

func scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, certificatesv1.AddToScheme, clusterv1.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func (tt unitTest) run(t *testing.T) unitResult {
	t.Helper()
	s := scheme(t)

	cluster := tt.cluster
	if cluster == nil {
		cluster = newCluster()
	}
	machine := tt.machine
	if machine == nil {
		machine = newMachine()
	}

	mgmt := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(cluster, machine).
		WithStatusSubresource(&clusterv1.Cluster{}, &clusterv1.Machine{}).
		WithIndex(&clusterv1.Machine{}, index.MachineNodeNameField, index.MachineByNodeName).
		Build()

	workloadObjs := make([]client.Object, 0, len(tt.csrs))
	for _, c := range tt.csrs {
		workloadObjs = append(workloadObjs, c)
	}
	workload := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(workloadObjs...).
		WithStatusSubresource(&certificatesv1.CertificateSigningRequest{}).
		WithIndex(&certificatesv1.CertificateSigningRequest{}, CSRUsernameField, CSRByUsername).
		Build()

	cc := clustercache.NewFakeClusterCache(workload, client.ObjectKey{Namespace: testNamespace, Name: testCluster}, watchCSRsName)
	if tt.disconnected {
		cc = clustercache.NewFakeEmptyClusterCache()
	}

	recorder := record.NewFakeRecorder(32)
	r := &MachineCSRReconciler{Client: mgmt, ClusterCache: cc, Recorder: recorder}
	if tt.reconciler != nil {
		tt.reconciler(r)
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(machine)})

	res := unitResult{err: err, csrs: map[string]*certificatesv1.CertificateSigningRequest{}, recorder: recorder}
	list := &certificatesv1.CertificateSigningRequestList{}
	if err := workload.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	for i := range list.Items {
		res.csrs[list.Items[i].Name] = &list.Items[i]
	}
	close(recorder.Events)
	for e := range recorder.Events {
		res.events = append(res.events, e)
	}
	return res
}

func approved(c *certificatesv1.CertificateSigningRequest) bool {
	for _, cond := range c.Status.Conditions {
		if cond.Type == certificatesv1.CertificateApproved && cond.Status == corev1.ConditionTrue {
			return cond.Reason == ApprovedReason
		}
	}
	return false
}

func denied(c *certificatesv1.CertificateSigningRequest) bool {
	for _, cond := range c.Status.Conditions {
		if cond.Type == certificatesv1.CertificateDenied && cond.Status == corev1.ConditionTrue {
			return cond.Reason == DeniedReason
		}
	}
	return false
}

func TestReconcileApprovesValidCSR(t *testing.T) {
	g := NewWithT(t)

	res := unitTest{csrs: []*certificatesv1.CertificateSigningRequest{validCSR("csr-1")}}.run(t)

	g.Expect(res.err).ToNot(HaveOccurred())
	g.Expect(approved(res.csrs["csr-1"])).To(BeTrue())
	g.Expect(res.events).To(ConsistOf(ContainSubstring("Normal CSRApproved Approved kubelet serving CertificateSigningRequest csr-1")))
}

func TestReconcileLeavesInvalidCSRPending(t *testing.T) {
	g := NewWithT(t)

	forged := csrtest.KubeletServing("csr-forged", testNode, csrtest.Request{
		DNSNames:    []string{testNode},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.10"), net.ParseIP("192.0.2.1")},
	})
	res := unitTest{csrs: []*certificatesv1.CertificateSigningRequest{forged}}.run(t)

	g.Expect(res.err).ToNot(HaveOccurred())
	g.Expect(res.csrs["csr-forged"].Status.Conditions).To(BeEmpty())
	g.Expect(res.events).To(ConsistOf(SatisfyAll(
		ContainSubstring("Warning CSRNotApproved"),
		ContainSubstring(`IP address "192.0.2.1" is not an address of the Machine`),
	)))
}

func TestReconcileDeniesInvalidCSRWhenConfigured(t *testing.T) {
	g := NewWithT(t)

	forged := csrtest.KubeletServing("csr-forged", testNode, csrtest.Request{DNSNames: []string{"evil.example"}})
	res := unitTest{
		csrs:       []*certificatesv1.CertificateSigningRequest{forged},
		reconciler: func(r *MachineCSRReconciler) { r.DenyInvalid = true },
	}.run(t)

	g.Expect(res.err).ToNot(HaveOccurred())
	g.Expect(denied(res.csrs["csr-forged"])).To(BeTrue())
	g.Expect(res.events).To(ConsistOf(ContainSubstring("Warning CSRDenied")))
}

func TestReconcileHandlesValidAndInvalidCSRsIndependently(t *testing.T) {
	g := NewWithT(t)

	forged := csrtest.KubeletServing("csr-forged", testNode, csrtest.Request{IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}})
	res := unitTest{csrs: []*certificatesv1.CertificateSigningRequest{validCSR("csr-valid"), forged}}.run(t)

	g.Expect(res.err).ToNot(HaveOccurred())
	g.Expect(approved(res.csrs["csr-valid"])).To(BeTrue())
	g.Expect(res.csrs["csr-forged"].Status.Conditions).To(BeEmpty())
}

func TestReconcileEnforcesValidationOptions(t *testing.T) {
	g := NewWithT(t)

	c := validCSR("csr-long")
	c.Spec.ExpirationSeconds = ptr.To[int32](86400)
	res := unitTest{
		csrs:       []*certificatesv1.CertificateSigningRequest{c},
		reconciler: func(r *MachineCSRReconciler) { r.ValidationOptions = csr.Options{MaxExpirationSeconds: 3600} },
	}.run(t)

	g.Expect(res.err).ToNot(HaveOccurred())
	g.Expect(res.csrs["csr-long"].Status.Conditions).To(BeEmpty())
	g.Expect(res.events).To(ConsistOf(ContainSubstring("exceeds the maximum of 3600")))
}

func TestReconcileIgnoresCSRsItShouldNotTouch(t *testing.T) {
	g := NewWithT(t)

	otherNode := csrtest.KubeletServing("csr-other-node", "other-node", csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}})

	alreadyApproved := validCSR("csr-approved")
	alreadyApproved.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{{
		Type: certificatesv1.CertificateApproved, Status: corev1.ConditionTrue, Reason: "SomeoneElse",
	}}

	alreadyDenied := validCSR("csr-denied")
	alreadyDenied.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{{
		Type: certificatesv1.CertificateDenied, Status: corev1.ConditionTrue, Reason: "SomeoneElse",
	}}

	clientCSR := validCSR("csr-client")
	clientCSR.Spec.SignerName = certificatesv1.KubeAPIServerClientKubeletSignerName

	res := unitTest{csrs: []*certificatesv1.CertificateSigningRequest{otherNode, alreadyApproved, alreadyDenied, clientCSR}}.run(t)

	g.Expect(res.err).ToNot(HaveOccurred())
	g.Expect(res.csrs["csr-other-node"].Status.Conditions).To(BeEmpty())
	g.Expect(res.csrs["csr-approved"].Status.Conditions).To(HaveLen(1))
	g.Expect(res.csrs["csr-approved"].Status.Conditions[0].Reason).To(Equal("SomeoneElse"))
	g.Expect(res.csrs["csr-denied"].Status.Conditions).To(HaveLen(1))
	g.Expect(res.csrs["csr-client"].Status.Conditions).To(BeEmpty())
	g.Expect(res.events).To(BeEmpty())
}

func TestReconcileSkips(t *testing.T) {
	tests := []struct {
		name string
		tt   unitTest
	}{
		{
			name: "Machine without a nodeRef",
			tt: unitTest{machine: func() *clusterv1.Machine {
				m := newMachine()
				m.Status.NodeRef = clusterv1.MachineNodeReference{}
				return m
			}()},
		},
		{
			name: "Cluster that does not match the selector",
			tt: unitTest{reconciler: func(r *MachineCSRReconciler) {
				r.ClusterSelector = labels.SelectorFromSet(labels.Set{"csr-approver": "enabled"})
			}},
		},
		{
			name: "paused Cluster",
			tt: unitTest{cluster: func() *clusterv1.Cluster {
				c := newCluster()
				c.Spec.Paused = ptr.To(true)
				return c
			}()},
		},
		{
			name: "paused Machine",
			tt: unitTest{machine: func() *clusterv1.Machine {
				m := newMachine()
				m.Annotations = map[string]string{clusterv1.PausedAnnotation: ""}
				return m
			}()},
		},
		{
			name: "control plane not initialized",
			tt: unitTest{cluster: func() *clusterv1.Cluster {
				c := newCluster()
				c.Status.Conditions = nil
				return c
			}()},
		},
		{
			name: "deleting Machine",
			tt: unitTest{machine: func() *clusterv1.Machine {
				m := newMachine()
				m.DeletionTimestamp = ptr.To(metav1.Now())
				m.Finalizers = []string{"test"}
				return m
			}()},
		},
		{
			name: "Machine without a cluster name label",
			tt: unitTest{machine: func() *clusterv1.Machine {
				m := newMachine()
				m.Labels = nil
				return m
			}()},
		},
		{
			name: "Machine whose Cluster does not exist",
			tt: unitTest{machine: func() *clusterv1.Machine {
				m := newMachine()
				m.Labels[clusterv1.ClusterNameLabel] = "missing"
				return m
			}()},
		},
		{
			name: "workload cluster not connected",
			tt:   unitTest{disconnected: true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			tc.tt.csrs = []*certificatesv1.CertificateSigningRequest{validCSR("csr-1")}

			res := tc.tt.run(t)

			g.Expect(res.err).ToNot(HaveOccurred())
			g.Expect(res.csrs["csr-1"].Status.Conditions).To(BeEmpty())
			g.Expect(res.events).To(BeEmpty())
		})
	}
}

func TestReconcileSelectedCluster(t *testing.T) {
	g := NewWithT(t)

	cluster := newCluster()
	cluster.Labels["csr-approver"] = "enabled"
	res := unitTest{
		cluster: cluster,
		csrs:    []*certificatesv1.CertificateSigningRequest{validCSR("csr-1")},
		reconciler: func(r *MachineCSRReconciler) {
			r.ClusterSelector = labels.SelectorFromSet(labels.Set{"csr-approver": "enabled"})
		},
	}.run(t)

	g.Expect(res.err).ToNot(HaveOccurred())
	g.Expect(approved(res.csrs["csr-1"])).To(BeTrue())
}

func TestCSRToMachine(t *testing.T) {
	s := scheme(t)

	sameCluster := newMachine()
	otherCluster := newMachine()
	otherCluster.Name = "other-machine"
	otherCluster.Labels[clusterv1.ClusterNameLabel] = "other-cluster"
	otherNamespace := newMachine()
	otherNamespace.Namespace = "other"

	mgmt := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(sameCluster, otherCluster, otherNamespace).
		WithIndex(&clusterv1.Machine{}, index.MachineNodeNameField, index.MachineByNodeName).
		Build()
	r := &MachineCSRReconciler{Client: mgmt}
	mapFn := r.csrToMachine(client.ObjectKey{Namespace: testNamespace, Name: testCluster})

	tests := []struct {
		name     string
		username string
		want     []string
	}{
		{name: "node with a Machine in the Cluster", username: csr.NodeUserPrefix + testNode, want: []string{testMachine}},
		{name: "node without a Machine", username: csr.NodeUserPrefix + "unknown"},
		{name: "non-node requester", username: "kubernetes-admin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			c := validCSR("csr")
			c.Spec.Username = tt.username

			var got []string
			for _, req := range mapFn(context.Background(), c) {
				g.Expect(req.Namespace).To(Equal(testNamespace))
				got = append(got, req.Name)
			}
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestPendingKubeletServingCSRPredicate(t *testing.T) {
	g := NewWithT(t)
	p := pendingKubeletServingCSR()

	g.Expect(p.Generic(eventFor(validCSR("pending")))).To(BeTrue())

	approvedCSR := validCSR("approved")
	approvedCSR.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{{Type: certificatesv1.CertificateApproved, Status: corev1.ConditionTrue}}
	g.Expect(p.Generic(eventFor(approvedCSR))).To(BeFalse())

	clientCSR := validCSR("client")
	clientCSR.Spec.SignerName = certificatesv1.KubeAPIServerClientSignerName
	g.Expect(p.Generic(eventFor(clientCSR))).To(BeFalse())
}

func eventFor(o client.Object) event.GenericEvent {
	return event.GenericEvent{Object: o}
}

func TestCSRByUsername(t *testing.T) {
	g := NewWithT(t)
	g.Expect(CSRByUsername(validCSR("csr"))).To(Equal([]string{csr.NodeUserPrefix + testNode}))
	g.Expect(CSRByUsername(&certificatesv1.CertificateSigningRequest{})).To(BeNil())
	g.Expect(CSRByUsername(&corev1.Node{})).To(BeNil())
}
