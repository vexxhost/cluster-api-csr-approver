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

package csr_test

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
	"net/url"
	"testing"

	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"

	"github.com/vexxhost/cluster-api-csr-approver/pkg/csr"
	"github.com/vexxhost/cluster-api-csr-approver/pkg/csr/csrtest"
)

const nodeName = "worker-0"

var machineAddresses = clusterv1.MachineAddresses{
	{Type: clusterv1.MachineHostName, Address: "worker-0"},
	{Type: clusterv1.MachineInternalDNS, Address: "worker-0.cluster.internal"},
	{Type: clusterv1.MachineInternalIP, Address: "10.0.0.10"},
	{Type: clusterv1.MachineExternalIP, Address: "203.0.113.10"},
	{Type: clusterv1.MachineInternalIP, Address: "fd00::10"},
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(c *certificatesv1.CertificateSigningRequest)
		request   *csrtest.Request
		addresses clusterv1.MachineAddresses
		opts      csr.Options
		wantErrs  []string
	}{
		{
			name: "valid request with hostname and internal IP",
			request: &csrtest.Request{
				DNSNames:    []string{"worker-0"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.10")},
			},
		},
		{
			name: "valid request with every address the Machine reports",
			request: &csrtest.Request{
				DNSNames:    []string{"worker-0", "worker-0.cluster.internal"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.10"), net.ParseIP("203.0.113.10"), net.ParseIP("fd00::10")},
			},
		},
		{
			name:    "valid request with only an IP",
			request: &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}},
		},
		{
			name:    "node name is allowed even when the Machine has no DNS addresses",
			request: &csrtest.Request{DNSNames: []string{"worker-0"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}},
			addresses: clusterv1.MachineAddresses{
				{Type: clusterv1.MachineInternalIP, Address: "10.0.0.10"},
			},
		},
		{
			name:    "DNS names are compared case-insensitively and ignore a trailing dot",
			request: &csrtest.Request{DNSNames: []string{"Worker-0.Cluster.Internal."}},
		},
		{
			name:    "IPv6 addresses are compared semantically",
			request: &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("fd00:0:0:0:0:0:0:10")}},
		},
		{
			name:    "Machine addresses reported with a CIDR suffix are accepted",
			request: &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}},
			addresses: clusterv1.MachineAddresses{
				{Type: clusterv1.MachineInternalIP, Address: "10.0.0.10/24"},
			},
		},
		{
			name:    "Hostname address that is an IP counts as an IP",
			request: &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}},
			addresses: clusterv1.MachineAddresses{
				{Type: clusterv1.MachineHostName, Address: "10.0.0.10"},
			},
		},
		{
			name: "RSA usages including key encipherment are accepted",
			mutate: func(c *certificatesv1.CertificateSigningRequest) {
				c.Spec.Usages = []certificatesv1.KeyUsage{
					certificatesv1.UsageKeyEncipherment,
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageServerAuth,
				}
			},
			request: &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}, Key: mustRSAKey(t)},
		},
		{
			name:     "IP that does not belong to the Machine",
			request:  &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10"), net.ParseIP("192.0.2.1")}},
			wantErrs: []string{`IP address "192.0.2.1" is not an address of the Machine`},
		},
		{
			name:     "DNS name that does not belong to the Machine",
			request:  &csrtest.Request{DNSNames: []string{"worker-0", "kubernetes.default.svc"}},
			wantErrs: []string{`DNS name "kubernetes.default.svc" is not an address of the Machine`},
		},
		{
			name:     "DNS name that only shares a prefix with the node name",
			request:  &csrtest.Request{DNSNames: []string{"worker-0.attacker.example"}},
			wantErrs: []string{`DNS name "worker-0.attacker.example" is not an address of the Machine`},
		},
		{
			name:      "Machine without addresses only allows its node name",
			request:   &csrtest.Request{DNSNames: []string{"worker-0"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}},
			addresses: clusterv1.MachineAddresses{},
			wantErrs:  []string{`IP address "10.0.0.10" is not an address of the Machine`},
		},
		{
			name:     "no subjectAltNames",
			request:  &csrtest.Request{},
			wantErrs: []string{"at least one DNS or IP subjectAltName is required"},
		},
		{
			name: "email subjectAltName",
			request: &csrtest.Request{
				IPAddresses: []net.IP{net.ParseIP("10.0.0.10")},
				Emails:      []string{"admin@example.com"},
			},
			wantErrs: []string{"email subjectAltNames are not allowed"},
		},
		{
			name: "URI subjectAltName",
			request: &csrtest.Request{
				IPAddresses: []net.IP{net.ParseIP("10.0.0.10")},
				URIs:        []*url.URL{{Scheme: "spiffe", Host: "example.com"}},
			},
			wantErrs: []string{"URI subjectAltNames are not allowed"},
		},
		{
			name: "common name for another node",
			request: &csrtest.Request{
				CommonName:  "system:node:worker-1",
				IPAddresses: []net.IP{net.ParseIP("10.0.0.10")},
			},
			wantErrs: []string{`subject common name "system:node:worker-1" does not match "system:node:worker-0"`},
		},
		{
			name: "wrong organization",
			request: &csrtest.Request{
				Organization: []string{"system:masters"},
				IPAddresses:  []net.IP{net.ParseIP("10.0.0.10")},
			},
			wantErrs: []string{"subject organization [system:masters] must be exactly [system:nodes]"},
		},
		{
			name: "extra organization",
			request: &csrtest.Request{
				Organization: []string{"system:nodes", "system:masters"},
				IPAddresses:  []net.IP{net.ParseIP("10.0.0.10")},
			},
			wantErrs: []string{"subject organization [system:nodes system:masters] must be exactly [system:nodes]"},
		},
		{
			name: "requested by another node",
			mutate: func(c *certificatesv1.CertificateSigningRequest) {
				c.Spec.Username = "system:node:worker-1"
			},
			request:  &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}},
			wantErrs: []string{`requested by "system:node:worker-1", expected "system:node:worker-0"`},
		},
		{
			name: "requested by a non-node user",
			mutate: func(c *certificatesv1.CertificateSigningRequest) {
				c.Spec.Username = "kubernetes-admin"
				c.Spec.Groups = []string{"system:masters", "system:authenticated"}
			},
			request: &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}},
			wantErrs: []string{
				`requested by "kubernetes-admin", expected "system:node:worker-0"`,
				`requester is not a member of group "system:nodes"`,
			},
		},
		{
			name: "client auth usage",
			mutate: func(c *certificatesv1.CertificateSigningRequest) {
				c.Spec.Usages = append(c.Spec.Usages, certificatesv1.UsageClientAuth)
			},
			request:  &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}},
			wantErrs: []string{"usages [client auth digital signature server auth] are not allowed"},
		},
		{
			name: "missing server auth usage",
			mutate: func(c *certificatesv1.CertificateSigningRequest) {
				c.Spec.Usages = []certificatesv1.KeyUsage{certificatesv1.UsageDigitalSignature}
			},
			request:  &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}},
			wantErrs: []string{"usages [digital signature] are not allowed"},
		},
		{
			name: "different signer",
			mutate: func(c *certificatesv1.CertificateSigningRequest) {
				c.Spec.SignerName = certificatesv1.KubeAPIServerClientKubeletSignerName
			},
			request:  &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}},
			wantErrs: []string{`signer "kubernetes.io/kube-apiserver-client-kubelet" is not "kubernetes.io/kubelet-serving"`},
		},
		{
			name: "expiration above the configured maximum",
			mutate: func(c *certificatesv1.CertificateSigningRequest) {
				c.Spec.ExpirationSeconds = ptr.To[int32](7200)
			},
			opts:     csr.Options{MaxExpirationSeconds: 3600},
			request:  &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}},
			wantErrs: []string{"expirationSeconds 7200 exceeds the maximum of 3600"},
		},
		{
			name: "expiration within the configured maximum",
			mutate: func(c *certificatesv1.CertificateSigningRequest) {
				c.Spec.ExpirationSeconds = ptr.To[int32](3600)
			},
			opts:    csr.Options{MaxExpirationSeconds: 3600},
			request: &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}},
		},
		{
			name: "garbage request",
			mutate: func(c *certificatesv1.CertificateSigningRequest) {
				c.Spec.Request = []byte("not a certificate request")
			},
			request:  &csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}},
			wantErrs: []string{"unable to parse certificate request"},
		},
		{
			name: "every problem is reported at once",
			mutate: func(c *certificatesv1.CertificateSigningRequest) {
				c.Spec.Usages = append(c.Spec.Usages, certificatesv1.UsageClientAuth)
			},
			request: &csrtest.Request{
				CommonName:  "system:node:worker-1",
				DNSNames:    []string{"evil.example"},
				IPAddresses: []net.IP{net.ParseIP("192.0.2.1")},
			},
			wantErrs: []string{
				"usages",
				"subject common name",
				`DNS name "evil.example"`,
				`IP address "192.0.2.1"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			c := csrtest.KubeletServing("csr", nodeName, *tt.request)
			if tt.mutate != nil {
				tt.mutate(c)
			}
			addresses := machineAddresses
			if tt.addresses != nil {
				addresses = tt.addresses
			}

			err := csr.Validate(c, nodeName, addresses, tt.opts)
			if len(tt.wantErrs) == 0 {
				g.Expect(err).ToNot(HaveOccurred())
				return
			}
			g.Expect(err).To(HaveOccurred())
			for _, want := range tt.wantErrs {
				g.Expect(err.Error()).To(ContainSubstring(want))
			}
		})
	}
}

func TestValidateRejectsTamperedSignature(t *testing.T) {
	g := NewWithT(t)

	c := csrtest.KubeletServing("csr", nodeName, csrtest.Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.10")}})
	// Flip a byte inside the base64 body so the PEM still decodes but the
	// signature no longer matches.
	body := []byte(string(c.Spec.Request))
	for i := len(body) - 40; i > 0; i-- {
		if body[i] != '\n' && body[i] != 'A' {
			body[i] = 'A'
			break
		}
	}
	c.Spec.Request = body

	err := csr.Validate(c, nodeName, machineAddresses, csr.Options{})
	g.Expect(err).To(HaveOccurred())
}

func TestNodeNameFromUsername(t *testing.T) {
	tests := []struct {
		username string
		want     string
		ok       bool
	}{
		{username: "system:node:worker-0", want: "worker-0", ok: true},
		{username: "system:node:", ok: false},
		{username: "system:serviceaccount:kube-system:default", ok: false},
		{username: "kubernetes-admin", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.username, func(t *testing.T) {
			g := NewWithT(t)
			got, ok := csr.NodeNameFromUsername(tt.username)
			g.Expect(ok).To(Equal(tt.ok))
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestIsPending(t *testing.T) {
	tests := []struct {
		name       string
		conditions []certificatesv1.CertificateSigningRequestCondition
		want       bool
	}{
		{name: "no conditions", want: true},
		{
			name:       "approved",
			conditions: []certificatesv1.CertificateSigningRequestCondition{{Type: certificatesv1.CertificateApproved, Status: corev1.ConditionTrue}},
		},
		{
			name:       "denied",
			conditions: []certificatesv1.CertificateSigningRequestCondition{{Type: certificatesv1.CertificateDenied, Status: corev1.ConditionTrue}},
		},
		{
			name:       "failed",
			conditions: []certificatesv1.CertificateSigningRequestCondition{{Type: certificatesv1.CertificateFailed, Status: corev1.ConditionTrue}},
		},
		{
			name:       "approved with legacy empty status",
			conditions: []certificatesv1.CertificateSigningRequestCondition{{Type: certificatesv1.CertificateApproved}},
		},
		{
			name:       "unrelated condition",
			conditions: []certificatesv1.CertificateSigningRequestCondition{{Type: "Custom", Status: corev1.ConditionTrue}},
			want:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			c := &certificatesv1.CertificateSigningRequest{Status: certificatesv1.CertificateSigningRequestStatus{Conditions: tt.conditions}}
			g.Expect(csr.IsPending(c)).To(Equal(tt.want))
		})
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
