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

// Package csr validates kubelet serving CertificateSigningRequests against the
// addresses that Cluster API reports for the Machine backing the requesting Node.
//
// The checks follow the guidance in the Kubernetes TLS bootstrapping docs: a
// serving CSR must come from the node itself, request only serving usages, and
// only carry DNS and IP subjectAltNames that belong to that node. Ownership of
// names is decided by Machine.status.addresses, which is written by the
// infrastructure provider in the management cluster and cannot be changed by
// the node.
package csr

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
)

const (
	// NodeUserPrefix is the prefix of the username kubelets authenticate with.
	NodeUserPrefix = "system:node:"

	// NodesGroup is the group all kubelets are a member of.
	NodesGroup = "system:nodes"
)

var (
	// requiredUsages and requiredUsagesNoRSA are the only usage sets the
	// kubernetes.io/kubelet-serving signer accepts. They mirror
	// ValidateKubeletServingCSR in k8s.io/kubernetes/pkg/apis/certificates.
	requiredUsages = sets.New(
		certificatesv1.UsageDigitalSignature,
		certificatesv1.UsageKeyEncipherment,
		certificatesv1.UsageServerAuth,
	)
	requiredUsagesNoRSA = sets.New(
		certificatesv1.UsageDigitalSignature,
		certificatesv1.UsageServerAuth,
	)
)

// Options tunes validation.
type Options struct {
	// MaxExpirationSeconds rejects CSRs whose spec.expirationSeconds is larger
	// than this value. Zero disables the check.
	MaxExpirationSeconds int32
}

// NodeNameFromUsername returns the node name for a kubelet username of the
// form "system:node:<name>".
func NodeNameFromUsername(username string) (string, bool) {
	name, ok := strings.CutPrefix(username, NodeUserPrefix)
	if !ok || name == "" {
		return "", false
	}
	return name, true
}

// IsKubeletServing returns true if the CSR targets the kubelet serving signer.
func IsKubeletServing(csr *certificatesv1.CertificateSigningRequest) bool {
	return csr.Spec.SignerName == certificatesv1.KubeletServingSignerName
}

// IsPending returns true if the CSR has not been approved, denied or failed.
func IsPending(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, c := range csr.Status.Conditions {
		switch c.Type {
		case certificatesv1.CertificateApproved, certificatesv1.CertificateDenied, certificatesv1.CertificateFailed:
			if c.Status == corev1.ConditionTrue || c.Status == "" {
				return false
			}
		}
	}
	return true
}

// Validate checks that csr is a kubelet serving request from nodeName whose
// subjectAltNames all belong to a Machine with the given addresses.
//
// It returns nil if the CSR can be approved. Otherwise it returns an aggregate
// error describing every problem found, suitable for events and logs.
func Validate(csr *certificatesv1.CertificateSigningRequest, nodeName string, addresses clusterv1.MachineAddresses, opts Options) error {
	if !IsKubeletServing(csr) {
		return fmt.Errorf("signer %q is not %q", csr.Spec.SignerName, certificatesv1.KubeletServingSignerName)
	}

	username := NodeUserPrefix + nodeName
	var errs []error

	if csr.Spec.Username != username {
		errs = append(errs, fmt.Errorf("requested by %q, expected %q", csr.Spec.Username, username))
	}
	if !slices.Contains(csr.Spec.Groups, NodesGroup) {
		errs = append(errs, fmt.Errorf("requester is not a member of group %q", NodesGroup))
	}

	usages := sets.New(csr.Spec.Usages...)
	if !usages.Equal(requiredUsages) && !usages.Equal(requiredUsagesNoRSA) {
		errs = append(errs, fmt.Errorf("usages %v are not allowed, expected %v or %v",
			sets.List(usages), sets.List(requiredUsages), sets.List(requiredUsagesNoRSA)))
	}

	if opts.MaxExpirationSeconds > 0 && csr.Spec.ExpirationSeconds != nil && *csr.Spec.ExpirationSeconds > opts.MaxExpirationSeconds {
		errs = append(errs, fmt.Errorf("expirationSeconds %d exceeds the maximum of %d", *csr.Spec.ExpirationSeconds, opts.MaxExpirationSeconds))
	}

	req, err := parseRequest(csr.Spec.Request)
	if err != nil {
		// Without a parsed request nothing else can be checked.
		return kerrors.NewAggregate(append(errs, err))
	}
	errs = append(errs, validateRequest(req, username, nodeName, addresses)...)

	return kerrors.NewAggregate(errs)
}

func parseRequest(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("unable to parse certificate request: no CERTIFICATE REQUEST PEM block found")
	}
	if extra, _ := pem.Decode(rest); extra != nil {
		return nil, errors.New("unable to parse certificate request: more than one PEM block found")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate request: %w", err)
	}
	if err := req.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid certificate request signature: %w", err)
	}
	return req, nil
}

func validateRequest(req *x509.CertificateRequest, username, nodeName string, addresses clusterv1.MachineAddresses) []error {
	var errs []error

	if req.Subject.CommonName != username {
		errs = append(errs, fmt.Errorf("subject common name %q does not match %q", req.Subject.CommonName, username))
	}
	if !slices.Equal(req.Subject.Organization, []string{NodesGroup}) {
		errs = append(errs, fmt.Errorf("subject organization %v must be exactly [%s]", req.Subject.Organization, NodesGroup))
	}
	if len(req.EmailAddresses) > 0 {
		errs = append(errs, errors.New("email subjectAltNames are not allowed"))
	}
	if len(req.URIs) > 0 {
		errs = append(errs, errors.New("URI subjectAltNames are not allowed"))
	}
	if len(req.DNSNames) == 0 && len(req.IPAddresses) == 0 {
		errs = append(errs, errors.New("at least one DNS or IP subjectAltName is required"))
	}

	allowedDNS, allowedIPs := allowedNames(nodeName, addresses)
	for _, name := range req.DNSNames {
		if !allowedDNS.Has(normalizeDNS(name)) {
			errs = append(errs, fmt.Errorf("DNS name %q is not an address of the Machine", name))
		}
	}
	for _, ip := range req.IPAddresses {
		if !slices.ContainsFunc(allowedIPs, ip.Equal) {
			errs = append(errs, fmt.Errorf("IP address %q is not an address of the Machine", ip.String()))
		}
	}

	return errs
}

// allowedNames returns the DNS names and IPs a node may put in its serving
// certificate. The node name is always allowed since the CSR is authenticated
// as that node. Any Machine address that parses as an IP is an allowed IP; the
// remaining Hostname, InternalDNS and ExternalDNS addresses are allowed DNS names.
func allowedNames(nodeName string, addresses clusterv1.MachineAddresses) (sets.Set[string], []net.IP) {
	dns := sets.New(normalizeDNS(nodeName))
	var ips []net.IP

	for _, a := range addresses {
		value := strings.TrimSpace(a.Address)
		if value == "" {
			continue
		}
		if ip := parseIP(value); ip != nil {
			ips = append(ips, ip)
			continue
		}
		switch a.Type {
		case clusterv1.MachineHostName, clusterv1.MachineInternalDNS, clusterv1.MachineExternalDNS:
			dns.Insert(normalizeDNS(value))
		}
	}

	return dns, ips
}

// parseIP parses an IP, accepting an optional CIDR suffix since some
// providers report addresses as prefixes.
func parseIP(value string) net.IP {
	if ip, _, err := net.ParseCIDR(value); err == nil {
		return ip
	}
	return net.ParseIP(value)
}

func normalizeDNS(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}
