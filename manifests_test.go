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
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/cluster-api/cmd/clusterctl/client/yamlprocessor"
)

// TestManifestVariablesHaveDefaults makes sure `clusterctl init --addon`
// works without any variables set. clusterctl treats a variable with an empty
// default as required, so every variable needs a non-empty default.
func TestManifestVariablesHaveDefaults(t *testing.T) {
	g := NewWithT(t)

	var files []string
	g.Expect(filepath.WalkDir("config", func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			files = append(files, path)
		}
		return err
	})).To(Succeed())
	g.Expect(files).ToNot(BeEmpty())

	processor := yamlprocessor.NewSimpleProcessor()
	for _, f := range files {
		data, err := os.ReadFile(f)
		g.Expect(err).ToNot(HaveOccurred())

		variables, err := processor.GetVariableMap(data)
		g.Expect(err).ToNot(HaveOccurred(), f)
		for name, def := range variables {
			g.Expect(def).ToNot(BeNil(), "%s: clusterctl variable %s needs a non-empty default", f, name)
		}

		// Rendering with no variables set must succeed.
		_, err = processor.Process(data, func(string) (string, error) { return "", os.ErrNotExist })
		g.Expect(err).ToNot(HaveOccurred(), f)
	}
}

// TestDefaultClusterSelector checks the default selector in the manifests
// handles every Cluster unless it opts out.
func TestDefaultClusterSelector(t *testing.T) {
	g := NewWithT(t)

	data, err := os.ReadFile(filepath.Join("config", "manager", "manager.yaml"))
	g.Expect(err).ToNot(HaveOccurred())
	variables, err := yamlprocessor.NewSimpleProcessor().GetVariableMap(data)
	g.Expect(err).ToNot(HaveOccurred())
	def := variables["CSR_APPROVER_CLUSTER_SELECTOR"]
	g.Expect(def).ToNot(BeNil())

	sel, err := parseClusterSelector(*def)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(sel.Matches(labels.Set{})).To(BeTrue())
	g.Expect(sel.Matches(labels.Set{"cni": "calico"})).To(BeTrue())
	g.Expect(sel.Matches(labels.Set{"csr-approver.vexxhost.com/disabled": "false"})).To(BeTrue())
	g.Expect(sel.Matches(labels.Set{"csr-approver.vexxhost.com/disabled": "true"})).To(BeFalse())
}
