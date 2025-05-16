// Copyright 2021-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package kubecertagent provides controllers that ensure a pod (the kube-cert-agent), is
// co-located with the Kubernetes controller manager so that Pinniped can access its signing keys.
package kubecertagent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/pflag"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/cache"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	appsv1informers "k8s.io/client-go/informers/apps/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"

	conciergeconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	configv1alpha1informers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions/config/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/issuerconfig"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/plog"
)

const (
	// ControllerManagerNamespace is the assumed namespace of the kube-controller-manager pod(s).
	ControllerManagerNamespace = "kube-system"

	// agentPodLabelKey is used to identify which pods are created by the kube-cert-agent
	// controllers.  These values should be updated when an incompatible change is made to
	// the kube-cert-agent pods.  Doing so will cause about a minute of downtime of the token
	// credential request API on upgrade because the new concierge pods will not be able to
	// fill their agentController.dynamicCertProvider cache until the new deployment has rolled
	// out.  This is exacerbated by our leader election which assumes that filling caches only
	// requires read requests.  On the incompatible kube-cert-agent upgrade case, we have to
	// issue a write request to fill a cache (which just points out how hacky this code is).
	//
	// On an upgrade to a new pinniped version, if the agent label has not changed, the new
	// pinniped code is basically saying that it is safe to use the old deployment forever
	// (because the update to the new deployment could fail indefinitely).  Therefore, if the
	// new pinniped code wants to guarantee that any change to the kube cert agent deployment
	// has rolled out before attempting to fetch the signer, it must update agentPodLabelValue.
	agentPodLabelKey   = "kube-cert-agent.pinniped.dev"
	agentPodLabelValue = "v3"

	// conciergeDefaultLabelKeyName is the name of the key of the label applied to all Concierge resources.
	// This name is determined in the YAML manifests, but this controller needs to treat it as a special case below.
	conciergeDefaultLabelKeyName = "app"

	ClusterInfoNamespace    = "kube-public"
	clusterInfoName         = "cluster-info"
	clusterInfoConfigMapKey = "kubeconfig"

	agentPodContainerName = "sleeper"
)

// AgentConfig is the configuration for the kube-cert-agent controller.
type AgentConfig struct {
	// Namespace in which agent pods will be created.
	Namespace string

	// ContainerImage specifies the container image used for the agent pods.
	ContainerImage string

	// NamePrefix will be prefixed to all agent pod names.
	NamePrefix string

	// ServiceAccountName is the service account under which to run the agent pods.
	ServiceAccountName string

	// ContainerImagePullSecrets is a list of names of Kubernetes Secret objects that will be used as
	// ImagePullSecrets on the kube-cert-agent pods.
	ContainerImagePullSecrets []string

	// CredentialIssuerName specifies the CredentialIssuer to be created/updated.
	CredentialIssuerName string

	// Labels to be applied to the CredentialIssuer and agent pods.
	Labels map[string]string

	// DiscoveryURLOverride is the Kubernetes server endpoint to report in the CredentialIssuer, overriding any
	// value discovered in the kube-public/cluster-info ConfigMap.
	DiscoveryURLOverride *string

	// PriorityClassName optionally sets the PriorityClassName for the agent's pod.
	PriorityClassName string
}

// Only select using the unique label which will not match the pods of any other Deployment.
// Older versions of Pinniped had multiple labels here.
func (a *AgentConfig) agentPodSelectorLabels() map[string]string {
	return map[string]string{agentPodLabelKey: agentPodLabelValue}
}

// Label the agent pod using the configured labels plus the unique label which we will use in the selector.
func (a *AgentConfig) agentPodLabels() map[string]string {
	allLabels := map[string]string{agentPodLabelKey: agentPodLabelValue}
	for k, v := range a.Labels {
		// Never label the agent pod with any label whose key is "app" because that could unfortunately match
		// the selector of the main Concierge Deployment. This is sadly inconsistent because all other resources
		// get labelled with the "app" label, but unfortunately the selector of the main Concierge Deployment is
		// an immutable field, so we cannot update it to make it use a more specific label without breaking upgrades.
		// Therefore, we take extra care here to avoid allowing the kube cert agent pods to match the selector of
		// the main Concierge Deployment. Note that older versions of Pinniped included this "app" label, so during
		// an upgrade we must take care to perform an update to remove it.
		if k != conciergeDefaultLabelKeyName {
			allLabels[k] = v
		}
	}
	return allLabels
}

func (a *AgentConfig) deploymentName() string {
	return strings.TrimSuffix(a.NamePrefix, "-")
}

type agentController struct {
	cfg                  AgentConfig
	client               *kubeclient.Client
	kubeSystemPods       corev1informers.PodInformer
	agentDeployments     appsv1informers.DeploymentInformer
	agentPods            corev1informers.PodInformer
	kubePublicConfigMaps corev1informers.ConfigMapInformer
	credentialIssuers    configv1alpha1informers.CredentialIssuerInformer
	executor             PodCommandExecutor
	dynamicCertProvider  dynamiccert.Private
	clock                clock.Clock
	log                  plog.Logger
	execCache            *cache.Expiring
}

var (
	// controllerManagerLabels are the Kubernetes labels we expect on the kube-controller-manager Pod.
	controllerManagerLabels = labels.SelectorFromSet(map[string]string{ //nolint:gochecknoglobals
		"component": "kube-controller-manager",
	})

	// agentLabels are the Kubernetes labels we always expect on the kube-controller-manager Pod.
	agentLabels = labels.SelectorFromSet(map[string]string{ //nolint:gochecknoglobals
		agentPodLabelKey: agentPodLabelValue,
	})
)

// NewAgentController returns a controller that manages the kube-cert-agent Deployment. It also is tasked with updating
// the CredentialIssuer with any errors that it encounters.
func NewAgentController(
	cfg AgentConfig,
	client *kubeclient.Client,
	kubeSystemPods corev1informers.PodInformer,
	agentDeployments appsv1informers.DeploymentInformer,
	agentPods corev1informers.PodInformer,
	kubePublicConfigMaps corev1informers.ConfigMapInformer,
	credentialIssuers configv1alpha1informers.CredentialIssuerInformer,
	dynamicCertProvider dynamiccert.Private,
) controllerlib.Controller {
	return newAgentController(
		cfg,
		client,
		kubeSystemPods,
		agentDeployments,
		agentPods,
		kubePublicConfigMaps,
		credentialIssuers,
		NewPodCommandExecutor(client.JSONConfig, client.Kubernetes),
		dynamicCertProvider,
		&clock.RealClock{},
		cache.NewExpiring(),
		plog.New(),
	)
}

func newAgentController(
	cfg AgentConfig,
	client *kubeclient.Client,
	kubeSystemPods corev1informers.PodInformer,
	agentDeployments appsv1informers.DeploymentInformer,
	agentPods corev1informers.PodInformer,
	kubePublicConfigMaps corev1informers.ConfigMapInformer,
	credentialIssuers configv1alpha1informers.CredentialIssuerInformer,
	podCommandExecutor PodCommandExecutor,
	dynamicCertProvider dynamiccert.Private,
	clock clock.Clock,
	execCache *cache.Expiring,
	log plog.Logger,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "kube-cert-agent-controller",
			Syncer: &agentController{
				cfg:                  cfg,
				client:               client,
				kubeSystemPods:       kubeSystemPods,
				agentDeployments:     agentDeployments,
				agentPods:            agentPods,
				kubePublicConfigMaps: kubePublicConfigMaps,
				credentialIssuers:    credentialIssuers,
				executor:             podCommandExecutor,
				dynamicCertProvider:  dynamicCertProvider,
				clock:                clock,
				log:                  log.WithName("kube-cert-agent-controller"),
				execCache:            execCache,
			},
		},
		controllerlib.WithInformer(
			kubeSystemPods,
			pinnipedcontroller.SimpleFilterWithSingletonQueue(func(obj metav1.Object) bool {
				return controllerManagerLabels.Matches(labels.Set(obj.GetLabels()))
			}),
			controllerlib.InformerOption{},
		),
		controllerlib.WithInformer(
			agentDeployments,
			pinnipedcontroller.SimpleFilterWithSingletonQueue(func(obj metav1.Object) bool {
				return obj.GetNamespace() == cfg.Namespace && obj.GetName() == cfg.deploymentName()
			}),
			controllerlib.InformerOption{},
		),
		controllerlib.WithInformer(
			agentPods,
			pinnipedcontroller.SimpleFilterWithSingletonQueue(func(obj metav1.Object) bool {
				return agentLabels.Matches(labels.Set(obj.GetLabels()))
			}),
			controllerlib.InformerOption{},
		),
		controllerlib.WithInformer(
			kubePublicConfigMaps,
			pinnipedcontroller.SimpleFilterWithSingletonQueue(func(obj metav1.Object) bool {
				return obj.GetNamespace() == ClusterInfoNamespace && obj.GetName() == clusterInfoName
			}),
			controllerlib.InformerOption{},
		),
		controllerlib.WithInformer(
			credentialIssuers,
			pinnipedcontroller.SimpleFilterWithSingletonQueue(func(obj metav1.Object) bool {
				return obj.GetName() == cfg.CredentialIssuerName
			}),
			controllerlib.InformerOption{},
		),
		// Be sure to run once even to make sure the CredentialIssuer is updated if there are no controller manager
		// pods. We should be able to pass an empty key since we don't use the key in the sync (we sync
		// the world).
		controllerlib.WithInitialEvent(controllerlib.Key{}),
	)
}

// Sync implements controllerlib.Syncer.
func (c *agentController) Sync(ctx controllerlib.Context) error {
	// Load the CredentialIssuer that we'll update with status.
	credIssuer, err := c.credentialIssuers.Lister().Get(c.cfg.CredentialIssuerName)
	if err != nil {
		return fmt.Errorf("could not get CredentialIssuer to update: %w", err)
	}

	// List kube-controller-manager Pods in the kube-system namespace by label.
	controllerManagerPods, err := c.kubeSystemPods.Lister().Pods(ControllerManagerNamespace).List(controllerManagerLabels)
	if err != nil {
		err := fmt.Errorf("could not list controller manager pods: %w", err)
		return c.failStrategyAndErr(ctx.Context, credIssuer, err, conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason)
	}

	// Pick the latest running pod, preferring pods on schedulable nodes when possible.
	// Draining or cordoning a node will mark it as unschedulable. See
	// https://kubernetes.io/docs/concepts/nodes/node/#manual-node-administration.
	// When that happens, we would prefer to relocate our agent pod to a different node
	// because the cluster admin has indicated that they would prefer those pods go elsewhere.
	newestControllerManager, err := c.newestRunningPodOnSchedulableNode(ctx.Context, controllerManagerPods)
	if err != nil {
		err := fmt.Errorf("error while looking for controller manager pod: %w", err)
		return c.failStrategyAndErr(ctx.Context, credIssuer, err, conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason)
	}

	// If there are no healthy controller manager pods, we alert the user that we can't find the keypair via
	// the CredentialIssuer.
	if newestControllerManager == nil {
		msg := fmt.Sprintf("could not find a healthy kube-controller-manager pod (%s)", pluralize(controllerManagerPods))
		if len(controllerManagerPods) == 0 {
			err = fmt.Errorf("%s: note that this error is the expected behavior for some cluster types, "+
				"including most cloud provider clusters (e.g. GKE, AKS, EKS)", msg)
		} else {
			err = errors.New(msg)
		}
		return c.failStrategyAndErr(ctx.Context, credIssuer, err, conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason)
	}

	depErr := c.createOrUpdateDeployment(ctx.Context, newestControllerManager)
	if depErr != nil {
		// it is fine if this call fails because a different concierge pod may have already created a compatible deployment
		// thus if the later code is able to find pods with the agent labels that we expect, we will attempt to use them
		// this means that we must always change the agent labels when we change the agent pods in an incompatible way
		depErr = fmt.Errorf("could not ensure agent deployment: %w", depErr)
	}

	// Find the latest healthy agent Pod in our namespace.
	agentPods, err := c.agentPods.Lister().Pods(c.cfg.Namespace).List(agentLabels)
	if err != nil {
		err := fmt.Errorf("could not list agent pods: %w", err)
		return c.failStrategyAndErr(ctx.Context, credIssuer, firstErr(depErr, err), conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason)
	}
	newestAgentPod := newestRunningPod(agentPods)

	// If there are no healthy controller agent pods, we alert the user that we can't find the keypair via
	// the CredentialIssuer.
	if newestAgentPod == nil {
		err := fmt.Errorf("could not find a healthy agent pod (%s)", pluralize(agentPods))
		return c.failStrategyAndErr(ctx.Context, credIssuer, firstErr(depErr, err), conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason)
	}

	// Load the Kubernetes API info from the kube-public/cluster-info ConfigMap.
	configMap, err := c.kubePublicConfigMaps.Lister().ConfigMaps(ClusterInfoNamespace).Get(clusterInfoName)
	if err != nil {
		err := fmt.Errorf("failed to get %s/%s configmap: %w", ClusterInfoNamespace, clusterInfoName, err)
		return c.failStrategyAndErr(ctx.Context, credIssuer, firstErr(depErr, err), conciergeconfigv1alpha1.CouldNotGetClusterInfoStrategyReason)
	}

	apiInfo, err := c.extractAPIInfo(configMap)
	if err != nil {
		err := fmt.Errorf("could not extract Kubernetes API endpoint info from %s/%s configmap: %w", ClusterInfoNamespace, clusterInfoName, err)
		return c.failStrategyAndErr(ctx.Context, credIssuer, firstErr(depErr, err), conciergeconfigv1alpha1.CouldNotGetClusterInfoStrategyReason)
	}

	// Load the certificate and key from the agent pod into our in-memory signer.
	if err := c.loadSigningKey(ctx.Context, newestAgentPod); err != nil {
		return c.failStrategyAndErr(ctx.Context, credIssuer, firstErr(depErr, err), conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason)
	}

	if depErr != nil {
		// if we get here, it means that we have successfully loaded a signing key but failed to reconcile the deployment.
		// mark the status as failed and re-kick the sync loop until we are happy with the state of the deployment.
		return c.failStrategyAndErr(ctx.Context, credIssuer, depErr, conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason)
	}

	// Set the CredentialIssuer strategy to successful.
	return issuerconfig.Update(ctx.Context, c.client.PinnipedConcierge, credIssuer, conciergeconfigv1alpha1.CredentialIssuerStrategy{
		Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
		Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
		Reason:         conciergeconfigv1alpha1.FetchedKeyStrategyReason,
		Message:        "key was fetched successfully",
		LastUpdateTime: metav1.NewTime(c.clock.Now()),
		Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
			Type:                          conciergeconfigv1alpha1.TokenCredentialRequestAPIFrontendType,
			TokenCredentialRequestAPIInfo: apiInfo,
		},
	})
}

func (c *agentController) loadSigningKey(ctx context.Context, agentPod *corev1.Pod) error {
	// If we remember successfully loading the key from this pod recently, we can skip this step and return immediately.
	if _, exists := c.execCache.Get(agentPod.UID); exists {
		return nil
	}

	// Exec into the agent pod and cat out the certificate and the key.
	outputJSON, err := c.executor.Exec(ctx, agentPod.Namespace, agentPod.Name, agentPodContainerName, "pinniped-concierge-kube-cert-agent", "print")
	if err != nil {
		return fmt.Errorf("could not exec into agent pod %s/%s: %w", agentPod.Namespace, agentPod.Name, err)
	}

	// Parse and decode the JSON output from the "pinniped-concierge-kube-cert-agent print" command.
	var output struct {
		Cert string `json:"tls.crt"`
		Key  string `json:"tls.key"`
	}
	if err := json.Unmarshal([]byte(outputJSON), &output); err != nil {
		return fmt.Errorf("failed to decode signing cert/key JSON from agent pod %s/%s: %w", agentPod.Namespace, agentPod.Name, err)
	}
	certPEM, err := base64.StdEncoding.DecodeString(output.Cert)
	if err != nil {
		return fmt.Errorf("failed to decode signing cert base64 from agent pod %s/%s: %w", agentPod.Namespace, agentPod.Name, err)
	}
	keyPEM, err := base64.StdEncoding.DecodeString(output.Key)
	if err != nil {
		return fmt.Errorf("failed to decode signing key base64 from agent pod %s/%s: %w", agentPod.Namespace, agentPod.Name, err)
	}

	// Load the certificate and key into the dynamic signer.
	if err := c.dynamicCertProvider.SetCertKeyContent(certPEM, keyPEM); err != nil {
		return fmt.Errorf("failed to set signing cert/key content from agent pod %s/%s: %w", agentPod.Namespace, agentPod.Name, err)
	}
	c.log.Info("successfully loaded signing key from agent pod into cache")

	// Remember that we've successfully loaded the key from this pod so we can skip the exec+load if nothing has changed.
	c.execCache.Set(agentPod.UID, struct{}{}, 15*time.Minute)
	return nil
}

func (c *agentController) createOrUpdateDeployment(ctx context.Context, newestControllerManager *corev1.Pod) error {
	// Build the expected Deployment based on the kube-controller-manager Pod as a template.
	expectedDeployment := c.newAgentDeployment(newestControllerManager)

	// Try to get the existing Deployment, if it exists.
	existingDeployment, err := c.agentDeployments.Lister().Deployments(expectedDeployment.Namespace).Get(expectedDeployment.Name)
	notFound := apierrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("could not get deployments: %w", err)
	}

	log := c.log.WithValues(
		"deployment", klog.KObj(expectedDeployment),
		"templatePod", klog.KObj(newestControllerManager),
	)

	// If the Deployment did not exist, create it and be done.
	if notFound {
		log.Info("creating new deployment")
		_, err := c.client.Kubernetes.AppsV1().Deployments(expectedDeployment.Namespace).Create(ctx, expectedDeployment, metav1.CreateOptions{})
		return err
	}

	// Update the spec of the Deployment to match our desired state.
	updatedDeployment := existingDeployment.DeepCopy()
	updatedDeployment.Spec = expectedDeployment.Spec
	updatedDeployment.ObjectMeta = mergeLabelsAndAnnotations(updatedDeployment.ObjectMeta, expectedDeployment.ObjectMeta)
	desireSelectorUpdate := !apiequality.Semantic.DeepEqual(updatedDeployment.Spec.Selector, existingDeployment.Spec.Selector)
	desireTemplateLabelsUpdate := !apiequality.Semantic.DeepEqual(updatedDeployment.Spec.Template.Labels, existingDeployment.Spec.Template.Labels)
	// The user might want to set PriorityClassName back to the default value of empty string. DeepDerivative() won't detect this case below.
	desirePriorityClassNameUpdate := updatedDeployment.Spec.Template.Spec.PriorityClassName != existingDeployment.Spec.Template.Spec.PriorityClassName

	// If the existing Deployment already matches our desired spec, we're done.
	if apiequality.Semantic.DeepDerivative(updatedDeployment, existingDeployment) {
		// DeepDerivative allows the map fields of updatedDeployment to be a subset of existingDeployment,
		// but we want to check that certain of those map fields are exactly equal before deciding to skip the update.
		if !desireSelectorUpdate && !desireTemplateLabelsUpdate && !desirePriorityClassNameUpdate {
			return nil // already equal enough, so skip update
		}
	}

	// Selector is an immutable field, so if we want to update it then we must delete and recreate the Deployment,
	// and then we're done. Older versions of Pinniped had multiple labels in the Selector, so to support upgrades from
	// those versions we take extra care to handle this case.
	if desireSelectorUpdate {
		log.Info("deleting deployment to update immutable Selector field")
		err = c.client.Kubernetes.AppsV1().Deployments(existingDeployment.Namespace).Delete(ctx, existingDeployment.Name, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{
				UID:             &existingDeployment.UID,
				ResourceVersion: &existingDeployment.ResourceVersion,
			},
		})
		if err != nil {
			return err
		}
		log.Info("creating new deployment to update immutable Selector field")
		_, err = c.client.Kubernetes.AppsV1().Deployments(expectedDeployment.Namespace).Create(ctx, expectedDeployment, metav1.CreateOptions{})
		return err
	}

	// Otherwise, update the Deployment.
	log.Info("updating existing deployment")
	_, err = c.client.Kubernetes.AppsV1().Deployments(updatedDeployment.Namespace).Update(ctx, updatedDeployment, metav1.UpdateOptions{})
	return err
}

func (c *agentController) failStrategyAndErr(ctx context.Context, credIssuer *conciergeconfigv1alpha1.CredentialIssuer, err error, reason conciergeconfigv1alpha1.StrategyReason) error {
	updateErr := issuerconfig.Update(ctx, c.client.PinnipedConcierge, credIssuer, conciergeconfigv1alpha1.CredentialIssuerStrategy{
		Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
		Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
		Reason:         reason,
		Message:        err.Error(),
		LastUpdateTime: metav1.NewTime(c.clock.Now()),
	})
	return utilerrors.NewAggregate([]error{err, updateErr})
}

func (c *agentController) extractAPIInfo(configMap *corev1.ConfigMap) (*conciergeconfigv1alpha1.TokenCredentialRequestAPIInfo, error) {
	kubeConfigYAML, kubeConfigPresent := configMap.Data[clusterInfoConfigMapKey]
	if !kubeConfigPresent {
		return nil, fmt.Errorf("missing %q key", clusterInfoConfigMapKey)
	}

	kubeconfig, err := clientcmd.Load([]byte(kubeConfigYAML))
	if err != nil {
		// We purposefully don't wrap "err" here because it's very verbose.
		return nil, fmt.Errorf("key %q does not contain a valid kubeconfig", clusterInfoConfigMapKey)
	}

	for _, v := range kubeconfig.Clusters {
		result := &conciergeconfigv1alpha1.TokenCredentialRequestAPIInfo{
			Server:                   v.Server,
			CertificateAuthorityData: base64.StdEncoding.EncodeToString(v.CertificateAuthorityData),
		}
		if c.cfg.DiscoveryURLOverride != nil {
			result.Server = *c.cfg.DiscoveryURLOverride
		}
		return result, nil
	}
	return nil, fmt.Errorf("kubeconfig in key %q does not contain any clusters", clusterInfoConfigMapKey)
}

func sortPodsByAgeNewestFirstAndFilterRunningOnly(pods []*corev1.Pod) []*corev1.Pod {
	// Copy and sort the pointers to the pods.
	sortedPods := make([]*corev1.Pod, len(pods))
	copy(sortedPods, pods)

	// Sort based on creation timestamp, breaking ties by name, sorting the newest first.
	slices.SortStableFunc(sortedPods, func(a, b *corev1.Pod) int {
		switch {
		case a.CreationTimestamp.Time.Equal(b.CreationTimestamp.Time):
			return strings.Compare(a.Name, b.Name)
		case a.CreationTimestamp.After(b.CreationTimestamp.Time):
			// Indicates a < b. We want the pod which was created more recently (after the other) to come first.
			return -1
		default:
			// Indicates a > b.
			return 1
		}
	})

	// Remove non-running pods.
	sortedPods = slices.DeleteFunc(sortedPods, func(pod *corev1.Pod) bool {
		return pod.Status.Phase != corev1.PodRunning
	})

	return sortedPods
}

// newestRunningPod takes a list of pods and returns the newest one with status.phase == "Running".
func newestRunningPod(pods []*corev1.Pod) *corev1.Pod {
	pods = sortPodsByAgeNewestFirstAndFilterRunningOnly(pods)
	if len(pods) == 0 {
		return nil
	}
	return pods[0]
}

// newestRunningPodOnSchedulableNode takes a list of pods and returns the newest one with status.phase == "Running",
// but prefers to return one that is running on a scheduleable node, when there is such an alternative available.
func (c *agentController) newestRunningPodOnSchedulableNode(ctx context.Context, pods []*corev1.Pod) (*corev1.Pod, error) {
	pods = sortPodsByAgeNewestFirstAndFilterRunningOnly(pods)
	if len(pods) == 0 {
		// Did not find any running pods.
		return nil, nil
	}
	if len(pods) == 1 {
		// Don't really have a choice, so skip the logic below as a performance optimization
		// because we already know the only possible answer.
		return pods[0], nil
	}

	// Get the nodes.
	nodes, err := c.client.Kubernetes.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	// Make a lookup table of the nodes by name.
	nodesByName := map[string]*corev1.Node{}
	for _, node := range nodes.Items {
		if len(node.Name) == 0 {
			// This shouldn't really happen, but would break our lookup table.
			return nil, fmt.Errorf("a node from the list of all nodes has no name")
		}
		nodesByName[node.Name] = &node
	}

	// Prefer to return the newest pod that is running on a scheduleable node, when possible.
	for _, pod := range pods {
		// NodeName field may be empty for an unscheduled pod, in which case this lookup will return nil.
		if node := nodesByName[pod.Spec.NodeName]; node != nil {
			if !node.Spec.Unschedulable {
				return pod, nil
			}
		}
	}

	// Fallback to using the newest pod regardless of node.
	return pods[0], nil
}

func (c *agentController) newAgentDeployment(controllerManagerPod *corev1.Pod) *appsv1.Deployment {
	var volumeMounts []corev1.VolumeMount
	if len(controllerManagerPod.Spec.Containers) > 0 {
		volumeMounts = controllerManagerPod.Spec.Containers[0].VolumeMounts
	}

	var imagePullSecrets []corev1.LocalObjectReference
	if len(c.cfg.ContainerImagePullSecrets) > 0 {
		imagePullSecrets = make([]corev1.LocalObjectReference, 0, len(c.cfg.ContainerImagePullSecrets))
		for _, name := range c.cfg.ContainerImagePullSecrets {
			imagePullSecrets = append(imagePullSecrets, corev1.LocalObjectReference{Name: name})
		}
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.cfg.deploymentName(),
			Namespace: c.cfg.Namespace,
			Labels:    c.cfg.Labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: metav1.SetAsLabelSelector(c.cfg.agentPodSelectorLabels()),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: c.cfg.agentPodLabels(),
				},
				Spec: corev1.PodSpec{
					TerminationGracePeriodSeconds: ptr.To[int64](0),
					ImagePullSecrets:              imagePullSecrets,
					Containers: []corev1.Container{
						{
							Name:            agentPodContainerName,
							Image:           c.cfg.ContainerImage,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         []string{"pinniped-concierge-kube-cert-agent", "sleep"},
							VolumeMounts:    volumeMounts,
							Env: []corev1.EnvVar{
								{
									Name: "CERT_PATH",
									Value: getContainerArgByName(controllerManagerPod,
										// See CLI flag docs at https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/
										[]string{"cluster-signing-cert-file", "cluster-signing-kube-apiserver-client-cert-file"},
										"/etc/kubernetes/ca/ca.pem",
									),
								},
								{
									Name: "KEY_PATH",
									Value: getContainerArgByName(controllerManagerPod,
										// See CLI flag docs at https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/
										[]string{"cluster-signing-key-file", "cluster-signing-kube-apiserver-client-key-file"},
										"/etc/kubernetes/ca/ca.key",
									),
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("32Mi"),
									corev1.ResourceCPU:    resource.MustParse("20m"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("32Mi"),
									// Must be explicitly 0 (not unset) to avoid problem described in https://github.com/vmware-tanzu/pinniped/issues/1507.
									corev1.ResourceCPU: resource.MustParse("0"),
								},
							},
						},
					},
					Volumes:                      controllerManagerPod.Spec.Volumes,
					RestartPolicy:                corev1.RestartPolicyAlways,
					NodeSelector:                 controllerManagerPod.Spec.NodeSelector,
					AutomountServiceAccountToken: ptr.To(false),
					ServiceAccountName:           c.cfg.ServiceAccountName,
					NodeName:                     controllerManagerPod.Spec.NodeName,
					Tolerations:                  controllerManagerPod.Spec.Tolerations,
					// We need to run the agent pod as root since the file permissions
					// on the cluster keypair usually restricts access to only root.
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:  ptr.To[int64](0),
						RunAsGroup: ptr.To[int64](0),
					},
					HostNetwork:       controllerManagerPod.Spec.HostNetwork,
					PriorityClassName: c.cfg.PriorityClassName,
				},
			},

			// Setting MinReadySeconds prevents the agent pods from being churned too quickly by the deployments controller.
			MinReadySeconds: 10,
		},
	}
}

func mergeLabelsAndAnnotations(existing metav1.ObjectMeta, desired metav1.ObjectMeta) metav1.ObjectMeta {
	result := existing.DeepCopy()
	for k, v := range desired.Labels {
		if result.Labels == nil {
			result.Labels = map[string]string{}
		}
		result.Labels[k] = v
	}
	for k, v := range desired.Annotations {
		if result.Annotations == nil {
			result.Annotations = map[string]string{}
		}
		result.Annotations[k] = v
	}
	return *result
}

func getContainerArgByName(pod *corev1.Pod, argsNames []string, fallbackValue string) string {
	for _, container := range pod.Spec.Containers {
		flagset := pflag.NewFlagSet("", pflag.ContinueOnError)
		flagset.ParseErrorsWhitelist = pflag.ParseErrorsWhitelist{UnknownFlags: true}
		parseResults := make([]string, len(argsNames))
		for i, argName := range argsNames {
			flagset.StringVar(&parseResults[i], argName, "", "")
		}
		_ = flagset.Parse(slices.Concat(container.Command, container.Args))
		for _, parseResult := range parseResults {
			if parseResult != "" {
				return parseResult
			}
		}
	}
	return fallbackValue
}

func pluralize(pods []*corev1.Pod) string {
	if len(pods) == 1 {
		return "1 candidate"
	}
	return fmt.Sprintf("%d candidates", len(pods))
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return fmt.Errorf("all errors were nil but should not have been")
}
