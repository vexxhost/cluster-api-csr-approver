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

// Package controllers contains the controller that approves kubelet serving
// CertificateSigningRequests in Cluster API workload clusters.
package controllers

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	"sigs.k8s.io/cluster-api/controllers/clustercache"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/cluster-api/util/annotations"
	"sigs.k8s.io/cluster-api/util/conditions"
	capicontrollerutil "sigs.k8s.io/cluster-api/util/controller"
	"sigs.k8s.io/cluster-api/util/index"
	"sigs.k8s.io/cluster-api/util/predicates"

	"github.com/vexxhost/cluster-api-csr-approver/pkg/csr"
)

const (
	// ControllerName is the name of the controller, used for logs, events and the user agent.
	ControllerName = "cluster-api-csr-approver"

	// CSRUsernameField indexes CertificateSigningRequests in workload clusters by spec.username.
	CSRUsernameField = "spec.username"

	// ApprovedReason is the reason set on the Approved condition of CSRs this controller approves.
	ApprovedReason = "MachineAddressesVerified"

	// DeniedReason is the reason set on the Denied condition of CSRs this controller denies.
	DeniedReason = "MachineAddressesMismatch"

	// EventReasonApproved is the event reason recorded on a Machine when one of its CSRs is approved.
	EventReasonApproved = "CSRApproved"

	// EventReasonNotApproved is the event reason recorded on a Machine when one of its CSRs fails validation.
	EventReasonNotApproved = "CSRNotApproved"

	// EventReasonDenied is the event reason recorded on a Machine when one of its CSRs is denied.
	EventReasonDenied = "CSRDenied"

	watchCSRsName = "machinecsr-watchCSRs"
)

// MachineCSRReconciler approves kubelet serving CertificateSigningRequests in
// workload clusters when every name they request belongs to the Machine that
// backs the requesting Node.
//
// It reconciles Machines in the management cluster. For every Cluster it
// handles, it registers a watch on kubelet serving CSRs in the workload cluster
// through the Cluster API ClusterCache and maps each CSR back to its Machine
// using the status.nodeRef.name index, the same way the Cluster API Machine
// controller maps Nodes to Machines.
type MachineCSRReconciler struct {
	// Client reads Clusters and Machines in the management cluster.
	Client client.Client

	// ClusterCache provides clients and watches for workload clusters.
	ClusterCache clustercache.ClusterCache

	// WatchFilterValue is the label value used to filter events prior to reconciliation.
	WatchFilterValue string

	// ClusterSelector limits which Clusters are handled. A nil selector handles every Cluster.
	ClusterSelector labels.Selector

	// DenyInvalid denies CSRs that fail validation instead of leaving them pending.
	// Leaving them pending is the default so other approvers can still act on them.
	DenyInvalid bool

	// ValidationOptions tune CSR validation.
	ValidationOptions csr.Options

	// Recorder records events on Machines. Optional; a recorder from the manager is used if nil.
	Recorder record.EventRecorder

	controller   capicontrollerutil.Controller
	predicateLog *logr.Logger
}

// +kubebuilder:rbac:groups=cluster.x-k8s.io,resources=clusters;machines,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// SetupWithManager registers the reconciler with mgr.
//
// The manager cache must have the index.MachineNodeNameField index on
// Machines, for example via index.ByMachineNode.
func (r *MachineCSRReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager, options controller.Options) error {
	if r.Client == nil || r.ClusterCache == nil {
		return errors.New("client and cluster cache must not be nil")
	}

	r.predicateLog = ptr.To(ctrl.LoggerFrom(ctx).WithValues("controller", "machinecsr"))
	clusterToMachines, err := util.ClusterToTypedObjectsMapper(mgr.GetClient(), &clusterv1.MachineList{}, mgr.GetScheme())
	if err != nil {
		return err
	}

	c, err := capicontrollerutil.NewControllerManagedBy(mgr, *r.predicateLog).
		For(&clusterv1.Machine{}).
		Named("machinecsr").
		WithOptions(options).
		WithEventFilter(predicates.ResourceHasFilterLabel(mgr.GetScheme(), *r.predicateLog, r.WatchFilterValue)).
		Watches(
			&clusterv1.Cluster{},
			handler.EnqueueRequestsFromMapFunc(clusterToMachines),
			predicates.Any(mgr.GetScheme(), *r.predicateLog,
				predicates.ClusterControlPlaneInitialized(mgr.GetScheme(), *r.predicateLog),
				// Pending CSRs are skipped while a Cluster is paused, so pick them up on unpause.
				predicates.ClusterPausedTransitions(mgr.GetScheme(), *r.predicateLog),
			),
			predicates.ResourceHasFilterLabel(mgr.GetScheme(), *r.predicateLog, r.WatchFilterValue),
		).
		// Reconcile all Machines of a Cluster when the ClusterCache connects to it,
		// so CSRs created while the connection was down are not missed.
		WatchesRawSource(r.ClusterCache.GetClusterSource("machinecsr", clusterToMachines)).
		Build(ctx, r)
	if err != nil {
		return fmt.Errorf("failed setting up with a controller manager: %w", err)
	}

	r.controller = c
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor(ControllerName) //nolint:staticcheck // Matches Cluster API controllers.
	}
	return nil
}

// Reconcile approves pending kubelet serving CSRs from the Node of a Machine.
func (r *MachineCSRReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	machine := &clusterv1.Machine{}
	if err := r.Client.Get(ctx, req.NamespacedName, machine); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if !machine.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	cluster, err := util.GetClusterFromMetadata(ctx, r.Client, machine.ObjectMeta)
	if err != nil {
		if errors.Is(err, util.ErrNoCluster) || apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	log = log.WithValues("Cluster", klog.KObj(cluster))
	ctx = ctrl.LoggerInto(ctx, log)

	if !r.handlesCluster(cluster) {
		log.V(5).Info("Skipping Machine because its Cluster does not match the cluster selector")
		return ctrl.Result{}, nil
	}
	if annotations.IsPaused(cluster, machine) {
		log.V(4).Info("Skipping Machine because it or its Cluster is paused")
		return ctrl.Result{}, nil
	}
	if !conditions.IsTrue(cluster, clusterv1.ClusterControlPlaneInitializedCondition) {
		log.V(4).Info("Skipping Machine because the control plane is not initialized yet")
		return ctrl.Result{}, nil
	}

	if err := r.watchClusterCSRs(ctx, cluster); err != nil {
		if errors.Is(err, clustercache.ErrClusterNotConnected) {
			// The ClusterCache source enqueues all Machines once the connection is up.
			log.V(4).Info("Requeue is not needed, waiting for the connection to the workload cluster", "reason", err.Error())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to watch CertificateSigningRequests: %w", err)
	}

	if !machine.Status.NodeRef.IsDefined() {
		// A Machine status update triggers a new reconcile once the Node is linked.
		return ctrl.Result{}, nil
	}
	nodeName := machine.Status.NodeRef.Name
	log = log.WithValues("Node", klog.KRef("", nodeName))
	ctx = ctrl.LoggerInto(ctx, log)

	remoteClient, err := r.ClusterCache.GetClient(ctx, util.ObjectKey(cluster))
	if err != nil {
		if errors.Is(err, clustercache.ErrClusterNotConnected) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	csrs := &certificatesv1.CertificateSigningRequestList{}
	if err := remoteClient.List(ctx, csrs, client.MatchingFields{CSRUsernameField: csr.NodeUserPrefix + nodeName}); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list CertificateSigningRequests: %w", err)
	}

	var errs []error
	for i := range csrs.Items {
		c := &csrs.Items[i]
		if !csr.IsKubeletServing(c) || !csr.IsPending(c) {
			continue
		}
		if err := r.reconcileCSR(ctx, remoteClient, machine, nodeName, c); err != nil {
			errs = append(errs, err)
		}
	}
	return ctrl.Result{}, kerrors.NewAggregate(errs)
}

func (r *MachineCSRReconciler) reconcileCSR(ctx context.Context, remoteClient client.Client, machine *clusterv1.Machine, nodeName string, c *certificatesv1.CertificateSigningRequest) error {
	log := ctrl.LoggerFrom(ctx).WithValues("CertificateSigningRequest", klog.KObj(c))

	validationErr := csr.Validate(c, nodeName, machine.Status.Addresses, r.ValidationOptions)
	if validationErr == nil {
		c.Status.Conditions = append(c.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
			Type:           certificatesv1.CertificateApproved,
			Status:         corev1.ConditionTrue,
			Reason:         ApprovedReason,
			Message:        fmt.Sprintf("Approved by %s: requested names match the addresses of Machine %s", ControllerName, klog.KObj(machine)),
			LastUpdateTime: metav1.Now(),
		})
		if err := remoteClient.SubResource("approval").Update(ctx, c); err != nil {
			return fmt.Errorf("failed to approve CertificateSigningRequest %s: %w", c.Name, err)
		}
		csrTotal.WithLabelValues(resultApproved).Inc()
		log.Info("Approved kubelet serving CertificateSigningRequest")
		r.Recorder.Eventf(machine, corev1.EventTypeNormal, EventReasonApproved, "Approved kubelet serving CertificateSigningRequest %s", c.Name)
		return nil
	}

	if !r.DenyInvalid {
		csrTotal.WithLabelValues(resultNotApproved).Inc()
		log.Info("Not approving kubelet serving CertificateSigningRequest", "reason", validationErr.Error())
		r.Recorder.Eventf(machine, corev1.EventTypeWarning, EventReasonNotApproved, "Not approving kubelet serving CertificateSigningRequest %s: %v", c.Name, validationErr)
		return nil
	}

	c.Status.Conditions = append(c.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:           certificatesv1.CertificateDenied,
		Status:         corev1.ConditionTrue,
		Reason:         DeniedReason,
		Message:        fmt.Sprintf("Denied by %s: %v", ControllerName, validationErr),
		LastUpdateTime: metav1.Now(),
	})
	if err := remoteClient.SubResource("approval").Update(ctx, c); err != nil {
		return fmt.Errorf("failed to deny CertificateSigningRequest %s: %w", c.Name, err)
	}
	csrTotal.WithLabelValues(resultDenied).Inc()
	log.Info("Denied kubelet serving CertificateSigningRequest", "reason", validationErr.Error())
	r.Recorder.Eventf(machine, corev1.EventTypeWarning, EventReasonDenied, "Denied kubelet serving CertificateSigningRequest %s: %v", c.Name, validationErr)
	return nil
}

func (r *MachineCSRReconciler) handlesCluster(cluster *clusterv1.Cluster) bool {
	return r.ClusterSelector == nil || r.ClusterSelector.Matches(labels.Set(cluster.Labels))
}

// watchClusterCSRs adds a watch on kubelet serving CSRs in the workload cluster.
// The ClusterCache only adds it once per connection.
func (r *MachineCSRReconciler) watchClusterCSRs(ctx context.Context, cluster *clusterv1.Cluster) error {
	return r.ClusterCache.Watch(ctx, util.ObjectKey(cluster), clustercache.NewWatcher(clustercache.WatcherOptions{
		Name:         watchCSRsName,
		Watcher:      r.controller,
		Kind:         &certificatesv1.CertificateSigningRequest{},
		EventHandler: handler.EnqueueRequestsFromMapFunc(r.csrToMachine(util.ObjectKey(cluster))),
		Predicates:   []predicate.TypedPredicate[client.Object]{pendingKubeletServingCSR()},
	}))
}

// csrToMachine maps a CSR in the workload cluster identified by clusterKey to
// the Machine whose status.nodeRef.name matches the requesting node.
func (r *MachineCSRReconciler) csrToMachine(clusterKey client.ObjectKey) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		c, ok := o.(*certificatesv1.CertificateSigningRequest)
		if !ok {
			panic(fmt.Sprintf("Expected a CertificateSigningRequest but got a %T", o))
		}
		nodeName, ok := csr.NodeNameFromUsername(c.Spec.Username)
		if !ok {
			return nil
		}

		machines := &clusterv1.MachineList{}
		if err := r.Client.List(ctx, machines,
			client.InNamespace(clusterKey.Namespace),
			client.MatchingLabels{clusterv1.ClusterNameLabel: clusterKey.Name},
			client.MatchingFields{index.MachineNodeNameField: nodeName},
		); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "Failed to list Machines for CertificateSigningRequest", "CertificateSigningRequest", klog.KObj(c))
			return nil
		}

		requests := make([]reconcile.Request, 0, len(machines.Items))
		for i := range machines.Items {
			requests = append(requests, reconcile.Request{NamespacedName: util.ObjectKey(&machines.Items[i])})
		}
		return requests
	}
}

func pendingKubeletServingCSR() predicate.Funcs {
	return predicate.NewPredicateFuncs(func(o client.Object) bool {
		c, ok := o.(*certificatesv1.CertificateSigningRequest)
		return ok && csr.IsKubeletServing(c) && csr.IsPending(c)
	})
}

// ClusterCacheCacheOptions returns the per-cluster cache options this
// controller needs: only kubelet serving CSRs are cached, indexed by username.
func ClusterCacheCacheOptions() clustercache.CacheOptions {
	return clustercache.CacheOptions{
		DefaultTransform: ctrlcache.TransformStripManagedFields(),
		ByObject: map[client.Object]ctrlcache.ByObject{
			&certificatesv1.CertificateSigningRequest{}: {
				Field: fields.OneTermEqualSelector("spec.signerName", certificatesv1.KubeletServingSignerName),
			},
		},
		Indexes: []clustercache.CacheOptionsIndex{{
			Object:       &certificatesv1.CertificateSigningRequest{},
			Field:        CSRUsernameField,
			ExtractValue: CSRByUsername,
		}},
	}
}

// CSRByUsername is the index function for CSRUsernameField.
func CSRByUsername(o client.Object) []string {
	c, ok := o.(*certificatesv1.CertificateSigningRequest)
	if !ok || c.Spec.Username == "" {
		return nil
	}
	return []string{c.Spec.Username}
}
