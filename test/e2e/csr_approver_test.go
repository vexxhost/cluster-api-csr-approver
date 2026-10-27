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
	"k8s.io/utils/ptr"

	capie2e "sigs.k8s.io/cluster-api/test/e2e"
	"sigs.k8s.io/cluster-api/test/framework"

	. "github.com/onsi/ginkgo/v2"
)

// workerMachineCountVariable sets the number of workers in the e2e config, so
// the same spec fits CAPD and a small devstack.
const workerMachineCountVariable = "CSR_E2E_WORKER_MACHINE_COUNT"

var _ = Describe("When creating a workload cluster with kubelet serving certificates [PR-Blocking]", func() {
	// The Cluster API quick start spec creates the cluster, waits for every
	// Machine, collects logs and cleans up. The CSR checks run once the
	// Machines are provisioned.
	capie2e.QuickStartSpec(ctx, func() capie2e.QuickStartSpecInput {
		workers := *e2eConfig.MustGetInt64PtrVariable(workerMachineCountVariable)
		return capie2e.QuickStartSpecInput{
			E2EConfig:                e2eConfig,
			ClusterctlConfigPath:     clusterctlConfigPath,
			BootstrapClusterProxy:    bootstrapClusterProxy,
			ArtifactFolder:           artifactFolder,
			SkipCleanup:              skipCleanup,
			ControlPlaneMachineCount: ptr.To[int64](1),
			WorkerMachineCount:       ptr.To(workers),
			PostMachinesProvisioned: func(managementClusterProxy framework.ClusterProxy, namespace, clusterName string) {
				spec := newCSRSpec(managementClusterProxy, namespace, clusterName)

				By("Checking every node has an approved, CA-signed kubelet serving certificate")
				spec.expectAllNodesApproved(int(1 + workers))

				By("Checking kube-apiserver can reach every kubelet while verifying its serving certificate")
				spec.expectLogsFromEveryNode()

				By("Checking a forged CertificateSigningRequest is left pending")
				spec.expectForgedCSRPending()

				By("Checking a new worker gets its kubelet serving certificate approved")
				spec.scaleWorkersAndExpectApproval(int32(workers + 1))
			},
		}
	})
})
