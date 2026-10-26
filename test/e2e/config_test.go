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
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
	"sigs.k8s.io/yaml"

	"sigs.k8s.io/cluster-api/cmd/clusterctl/client/yamlprocessor"
)

// frameworkVariables are set by the Cluster API test framework when it
// renders a cluster template.
var frameworkVariables = map[string]bool{
	"CLUSTER_NAME":                true,
	"NAMESPACE":                   true,
	"KUBERNETES_VERSION":          true,
	"CONTROL_PLANE_MACHINE_COUNT": true,
	"WORKER_MACHINE_COUNT":        true,
	"CNI_RESOURCES":               true,
}

// TestClusterTemplateVariablesAreSet renders the e2e cluster template, with
// the CNI manifest it embeds, through clusterctl's variable processor and
// checks every variable is provided. This runs without Docker, so mistakes
// show up in seconds instead of after a kind cluster is created.
func TestClusterTemplateVariablesAreSet(t *testing.T) {
	g := NewWithT(t)

	raw, err := os.ReadFile(filepath.Join("config", "e2e.yaml"))
	g.Expect(err).ToNot(HaveOccurred())
	var config struct {
		Variables map[string]string `json:"variables"`
	}
	g.Expect(yaml.Unmarshal(raw, &config)).To(Succeed())

	g.Expect(config.Variables).To(HaveKey("CNI"))
	files := []string{
		filepath.Join("data", "infrastructure-docker", "cluster-template.yaml"),
		config.Variables["CNI"],
	}

	processor := yamlprocessor.NewSimpleProcessor()
	for _, f := range files {
		data, err := os.ReadFile(f)
		g.Expect(err).ToNot(HaveOccurred())

		variables, err := processor.GetVariableMap(data)
		g.Expect(err).ToNot(HaveOccurred(), f)
		for name, def := range variables {
			if def != nil || frameworkVariables[name] {
				continue
			}
			g.Expect(config.Variables).To(HaveKey(name), "%s uses %s, which test/e2e/config/e2e.yaml does not set", f, name)
		}
	}
}
