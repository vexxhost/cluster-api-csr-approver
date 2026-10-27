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
	"strings"
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
	"CCM_RESOURCES":               true,
}

// environmentVariables are secrets or runtime values a CI workflow exports
// instead of the e2e config setting them.
var environmentVariables = map[string]map[string]string{
	"openstack.yaml": {
		"OPENSTACK_CLOUD_YAML_B64":          "../../.github/workflows/e2e-openstack.yml",
		"OPENSTACK_CLOUD_PROVIDER_CONF_B64": "../../.github/workflows/e2e-openstack.yml",
	},
}

type e2eConfigFile struct {
	Providers []struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Versions []struct {
			Files []struct {
				SourcePath string `json:"sourcePath"`
			} `json:"files"`
		} `json:"versions"`
	} `json:"providers"`
	Variables map[string]string `json:"variables"`
}

// TestClusterTemplateVariablesAreSet renders every e2e cluster template, with
// the manifests it embeds, through clusterctl's variable processor and checks
// every variable is provided. This runs without Docker or OpenStack, so
// mistakes show up in seconds instead of after a management cluster exists.
func TestClusterTemplateVariablesAreSet(t *testing.T) {
	configs, err := filepath.Glob(filepath.Join("config", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) == 0 {
		t.Fatal("no e2e configs found")
	}

	for _, configPath := range configs {
		t.Run(filepath.Base(configPath), func(t *testing.T) {
			g := NewWithT(t)

			raw, err := os.ReadFile(configPath)
			g.Expect(err).ToNot(HaveOccurred())
			var config e2eConfigFile
			g.Expect(yaml.Unmarshal(raw, &config)).To(Succeed())

			// Cluster templates are attached to the infrastructure provider
			// and resolved relative to the config file, like the framework does.
			var files []string
			for _, p := range config.Providers {
				if p.Type != "InfrastructureProvider" {
					continue
				}
				for _, v := range p.Versions {
					for _, f := range v.Files {
						if strings.HasPrefix(filepath.Base(f.SourcePath), "cluster-template") {
							files = append(files, filepath.Join(filepath.Dir(configPath), f.SourcePath))
						}
					}
				}
			}
			g.Expect(files).ToNot(BeEmpty(), "no cluster templates found")

			// CNI and CCM manifests are inlined into the templates and resolved
			// relative to the test package, like the suite does.
			g.Expect(config.Variables).To(HaveKey("CNI"))
			for _, v := range []string{"CNI", "CCM"} {
				if path, ok := config.Variables[v]; ok {
					files = append(files, path)
				}
			}

			env := environmentVariables[filepath.Base(configPath)]
			for name, workflow := range env {
				data, err := os.ReadFile(workflow)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(string(data)).To(ContainSubstring(name), "%s must export %s", workflow, name)
			}

			processor := yamlprocessor.NewSimpleProcessor()
			for _, f := range files {
				data, err := os.ReadFile(f)
				g.Expect(err).ToNot(HaveOccurred())

				variables, err := processor.GetVariableMap(data)
				g.Expect(err).ToNot(HaveOccurred(), f)
				for name, def := range variables {
					if def != nil || frameworkVariables[name] || env[name] != "" {
						continue
					}
					g.Expect(config.Variables).To(HaveKey(name), "%s uses %s, which %s does not set", f, name, configPath)
				}
			}
		})
	}
}
