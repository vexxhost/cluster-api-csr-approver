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

// Package csrtest builds kubelet serving CertificateSigningRequests for tests.
package csrtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"

	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vexxhost/cluster-api-csr-approver/pkg/csr"
)

// Request describes the x509 certificate request to generate.
type Request struct {
	// CommonName defaults to "system:node:<NodeName>".
	CommonName string
	// Organization defaults to ["system:nodes"].
	Organization []string
	DNSNames     []string
	IPAddresses  []net.IP
	Emails       []string
	URIs         []*url.URL
	// Key defaults to a fresh ECDSA P-256 key.
	Key crypto.Signer
}

// PEM returns a PEM encoded x509 certificate request for nodeName.
func PEM(nodeName string, r Request) ([]byte, error) {
	if r.CommonName == "" {
		r.CommonName = csr.NodeUserPrefix + nodeName
	}
	if r.Organization == nil {
		r.Organization = []string{csr.NodesGroup}
	}
	if r.Key == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		r.Key = key
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: r.CommonName, Organization: r.Organization},
		DNSNames:       r.DNSNames,
		IPAddresses:    r.IPAddresses,
		EmailAddresses: r.Emails,
		URIs:           r.URIs,
	}, r.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// MustPEM is PEM that panics on error.
func MustPEM(nodeName string, r Request) []byte {
	b, err := PEM(nodeName, r)
	if err != nil {
		panic(err)
	}
	return b
}

// KubeletServing returns a kubelet serving CSR object for nodeName, as the
// kubelet would create it. The username and groups are what the API server
// would set when the kubelet authenticates; they are ignored on create.
func KubeletServing(name, nodeName string, r Request) *certificatesv1.CertificateSigningRequest {
	return &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    MustPEM(nodeName, r),
			SignerName: certificatesv1.KubeletServingSignerName,
			Usages: []certificatesv1.KeyUsage{
				certificatesv1.UsageDigitalSignature,
				certificatesv1.UsageServerAuth,
			},
			Username: csr.NodeUserPrefix + nodeName,
			Groups:   []string{csr.NodesGroup, "system:authenticated"},
		},
	}
}
