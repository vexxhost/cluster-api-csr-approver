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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	"sigs.k8s.io/cluster-api/controllers/clustercache"
	"sigs.k8s.io/cluster-api/util/index"
)

// skipLabel opts a Cluster out of the reconciler started by the test suite.
const skipLabel = "csr-approver.test/skip"

var (
	env        *envtest.Environment
	envConfig  *rest.Config
	envClient  client.Client
	envScheme  = runtime.NewScheme()
	envEnabled bool
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("REQUIRE_ENVTEST") != "" {
			fmt.Fprintln(os.Stderr, "REQUIRE_ENVTEST is set but KUBEBUILDER_ASSETS is empty; run tests with `make test`")
			return 1
		}
		fmt.Fprintln(os.Stderr, "KUBEBUILDER_ASSETS is not set, envtest integration tests will be skipped")
		return m.Run()
	}

	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, certificatesv1.AddToScheme, rbacv1.AddToScheme, clusterv1.AddToScheme,
	} {
		if err := add(envScheme); err != nil {
			panic(err)
		}
	}

	crdPath, err := capiCRDPath()
	if err != nil {
		panic(err)
	}
	env = &envtest.Environment{
		CRDDirectoryPaths:     []string{crdPath},
		ErrorIfCRDPathMissing: true,
		Scheme:                envScheme,
	}
	envConfig, err = env.Start()
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := env.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "failed to stop envtest:", err)
		}
	}()

	envClient, err = client.New(envConfig, client.Options{Scheme: envScheme})
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctrl.SetLogger(klog.Background())

	if err := allowNodesToCreateCSRs(ctx); err != nil {
		panic(err)
	}

	mgr, err := ctrl.NewManager(envConfig, ctrl.Options{
		Scheme:  envScheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		panic(err)
	}
	if err := index.ByMachineNode(ctx, mgr); err != nil {
		panic(err)
	}

	selector, err := labels.Parse(skipLabel + "!=true")
	if err != nil {
		panic(err)
	}
	cc, err := clustercache.SetupWithManager(ctx, mgr, clustercache.Options{
		SecretClient:  mgr.GetClient(),
		Cache:         ClusterCacheCacheOptions(),
		Client:        clustercache.ClientOptions{UserAgent: ControllerName},
		ClusterFilter: func(c *clusterv1.Cluster) bool { return selector.Matches(labels.Set(c.Labels)) },
	}, controller.Options{MaxConcurrentReconciles: 10})
	if err != nil {
		panic(err)
	}
	if err := (&MachineCSRReconciler{
		Client:          mgr.GetClient(),
		ClusterCache:    cc,
		ClusterSelector: selector,
	}).SetupWithManager(ctx, mgr, controller.Options{MaxConcurrentReconciles: 10}); err != nil {
		panic(err)
	}

	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic(err)
		}
	}()
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		panic("manager cache did not sync")
	}

	envEnabled = true
	return m.Run()
}

func requireEnvtest(t *testing.T) {
	t.Helper()
	if !envEnabled {
		t.Skip("envtest is not available, set KUBEBUILDER_ASSETS to run integration tests")
	}
}

// capiCRDPath returns the directory with the Cluster API core CRDs from the
// module cache, so the CRDs always match the Cluster API version in go.mod.
func capiCRDPath() (string, error) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "sigs.k8s.io/cluster-api").Output()
	if err != nil {
		return "", fmt.Errorf("failed to locate sigs.k8s.io/cluster-api: %w", err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "core", "config", "crd", "bases"), nil
}

// allowNodesToCreateCSRs grants kubelets permission to create CSRs. A real
// cluster gets this from the Node authorizer and kubeadm bindings, which
// envtest does not configure.
func allowNodesToCreateCSRs(ctx context.Context) error {
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "test-nodes-create-csrs"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{certificatesv1.GroupName},
			Resources: []string{"certificatesigningrequests"},
			Verbs:     []string{"create", "get", "list", "watch"},
		}},
	}
	if err := envClient.Create(ctx, role); err != nil {
		return err
	}
	return envClient.Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role.Name},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: "system:nodes"}},
	})
}

// eventually and consistently are the default timings for integration tests.
var (
	eventually   = []any{30 * time.Second, 200 * time.Millisecond}
	consistently = []any{3 * time.Second, 200 * time.Millisecond}
)
