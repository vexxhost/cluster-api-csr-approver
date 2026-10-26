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

package main

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/labels"
)

func TestParseClusterSelector(t *testing.T) {
	g := NewWithT(t)

	sel, err := parseClusterSelector("")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(sel).To(BeNil())

	sel, err = parseClusterSelector("csr-approver.vexxhost.com/enabled=true,env in (prod)")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(sel.Matches(labels.Set{"csr-approver.vexxhost.com/enabled": "true", "env": "prod"})).To(BeTrue())
	g.Expect(sel.Matches(labels.Set{"env": "prod"})).To(BeFalse())

	_, err = parseClusterSelector("a in (")
	g.Expect(err).To(HaveOccurred())
}

func TestParseValidationOptions(t *testing.T) {
	g := NewWithT(t)

	opts, err := parseValidationOptions(0)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(opts.MaxExpirationSeconds).To(BeZero())

	opts, err = parseValidationOptions(720 * time.Hour)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(opts.MaxExpirationSeconds).To(Equal(int32(2592000)))

	_, err = parseValidationOptions(-time.Second)
	g.Expect(err).To(HaveOccurred())

	_, err = parseValidationOptions(100 * 365 * 24 * time.Hour)
	g.Expect(err).To(HaveOccurred())
}
