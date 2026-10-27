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
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	capie2e "sigs.k8s.io/cluster-api/test/e2e"
	"sigs.k8s.io/cluster-api/test/framework"
	"sigs.k8s.io/cluster-api/test/framework/bootstrap"
	"sigs.k8s.io/cluster-api/test/framework/clusterctl"
)

const (
	// ccmPath and ccmResources mirror capie2e.CNIPath and capie2e.CNIResources
	// for the cloud controller manager manifest.
	ccmPath      = "CCM"
	ccmResources = "CCM_RESOURCES"
)

var (
	ctx = ctrl.SetupSignalHandler()

	// Flags.
	configPath         string
	artifactFolder     string
	skipCleanup        bool
	useExistingCluster bool

	// Shared state, set up once in SynchronizedBeforeSuite.
	e2eConfig                *clusterctl.E2EConfig
	clusterctlConfigPath     string
	bootstrapClusterProvider bootstrap.ClusterProvider
	bootstrapClusterProxy    framework.ClusterProxy
)

func init() {
	flag.StringVar(&configPath, "e2e.config", "", "path to the e2e config file")
	flag.StringVar(&artifactFolder, "e2e.artifacts-folder", "", "folder where e2e test artifact should be stored")
	flag.BoolVar(&skipCleanup, "e2e.skip-resource-cleanup", false, "if true, the resource cleanup after tests will be skipped")
	flag.BoolVar(&useExistingCluster, "e2e.use-existing-cluster", false, "if true, the test uses the current cluster instead of creating a new one (default discovery rules apply)")
}

func TestE2E(t *testing.T) {
	ctrl.SetLogger(klog.Background())
	RegisterFailHandler(Fail)
	RunSpecs(t, "cluster-api-csr-approver-e2e")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	Expect(configPath).To(BeAnExistingFile(), "Invalid test suite argument. e2e.config should be an existing file.")
	Expect(os.MkdirAll(artifactFolder, 0o755)).To(Succeed(), "Invalid test suite argument. Can't create e2e.artifacts-folder %q", artifactFolder)

	By("Loading the e2e test configuration from " + configPath)
	e2eConfig = clusterctl.LoadE2EConfig(ctx, clusterctl.LoadE2EConfigInput{ConfigPath: configPath})
	Expect(e2eConfig).NotTo(BeNil())

	By("Creating a clusterctl local repository into " + artifactFolder)
	createRepositoryInput := clusterctl.CreateRepositoryInput{
		E2EConfig:        e2eConfig,
		RepositoryFolder: filepath.Join(artifactFolder, "repository"),
	}
	// Inject the CNI manifest into the ClusterResourceSet ConfigMap of the
	// cluster template, the same way the Cluster API e2e suite does.
	cniPath := e2eConfig.MustGetVariable(capie2e.CNIPath)
	Expect(cniPath).To(BeAnExistingFile(), "The %s variable should resolve to an existing file", capie2e.CNIPath)
	createRepositoryInput.RegisterClusterResourceSetConfigMapTransformation(cniPath, capie2e.CNIResources)
	// Providers with an external cloud controller manager (e.g. CAPO) get it
	// the same way, like the CAPO e2e suite does.
	if e2eConfig.HasVariable(ccmPath) {
		ccm := e2eConfig.MustGetVariable(ccmPath)
		Expect(ccm).To(BeAnExistingFile(), "The %s variable should resolve to an existing file", ccmPath)
		createRepositoryInput.RegisterClusterResourceSetConfigMapTransformation(ccm, ccmResources)
	}
	clusterctlConfigPath = clusterctl.CreateRepository(ctx, createRepositoryInput)
	Expect(clusterctlConfigPath).To(BeAnExistingFile())

	By("Setting up the bootstrap cluster")
	scheme := initScheme()
	kubeconfigPath := ""
	if !useExistingCluster {
		bootstrapClusterProvider = bootstrap.CreateKindBootstrapClusterAndLoadImages(ctx, bootstrap.CreateKindBootstrapClusterAndLoadImagesInput{
			Name:               e2eConfig.ManagementClusterName,
			RequiresDockerSock: e2eConfig.HasDockerProvider(),
			Images:             e2eConfig.Images,
			LogFolder:          filepath.Join(artifactFolder, "kind"),
		})
		Expect(bootstrapClusterProvider).NotTo(BeNil(), "Failed to create a bootstrap cluster")
		kubeconfigPath = bootstrapClusterProvider.GetKubeconfigPath()
	}
	bootstrapClusterProxy = newBootstrapClusterProxy(kubeconfigPath, scheme)
	Expect(bootstrapClusterProxy).NotTo(BeNil())

	By("Initializing the bootstrap cluster with Cluster API, the infrastructure provider and cluster-api-csr-approver")
	clusterctl.InitManagementClusterAndWatchControllerLogs(ctx, clusterctl.InitManagementClusterAndWatchControllerLogsInput{
		ClusterProxy:              bootstrapClusterProxy,
		ClusterctlConfigPath:      clusterctlConfigPath,
		InfrastructureProviders:   e2eConfig.InfrastructureProviders(),
		RuntimeExtensionProviders: e2eConfig.RuntimeExtensionProviders(),
		AddonProviders:            e2eConfig.AddonProviders(),
		LogFolder:                 filepath.Join(artifactFolder, "clusters", bootstrapClusterProxy.GetName()),
	}, e2eConfig.GetIntervals(bootstrapClusterProxy.GetName(), "wait-controllers")...)

	return []byte(strings.Join([]string{artifactFolder, configPath, clusterctlConfigPath, bootstrapClusterProxy.GetKubeconfigPath()}, ","))
}, func(data []byte) {
	parts := strings.Split(string(data), ",")
	Expect(parts).To(HaveLen(4))

	artifactFolder = parts[0]
	e2eConfig = clusterctl.LoadE2EConfig(ctx, clusterctl.LoadE2EConfigInput{ConfigPath: parts[1]})
	clusterctlConfigPath = parts[2]
	bootstrapClusterProxy = newBootstrapClusterProxy(parts[3], initScheme())
})

var _ = SynchronizedAfterSuite(func() {}, func() {
	if skipCleanup {
		return
	}
	By("Tearing down the management cluster")
	if bootstrapClusterProxy != nil {
		bootstrapClusterProxy.Dispose(ctx)
	}
	if bootstrapClusterProvider != nil {
		bootstrapClusterProvider.Dispose(ctx)
	}
})

// newBootstrapClusterProxy returns the management cluster proxy. Machine logs
// are collected with docker exec when the workload cluster runs on CAPD.
func newBootstrapClusterProxy(kubeconfigPath string, scheme *runtime.Scheme) framework.ClusterProxy {
	var opts []framework.Option
	if e2eConfig.HasDockerProvider() {
		opts = append(opts, framework.WithMachineLogCollector(framework.DockerLogCollector{}))
	}
	return framework.NewClusterProxy("bootstrap", kubeconfigPath, scheme, opts...)
}

func initScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	framework.TryAddDefaultSchemes(scheme)
	// The framework defaults don't include certificates.k8s.io, which the
	// checks need to read CertificateSigningRequests in workload clusters.
	Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed())
	Expect(clusterv1.AddToScheme(scheme)).To(Succeed())
	return scheme
}
