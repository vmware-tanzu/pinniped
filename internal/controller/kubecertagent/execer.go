// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"encoding/base64"
	"fmt"

	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/clock"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/issuerconfig"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/dynamiccert"
)

const (
	ClusterInfoNamespace    = "kube-public"
	clusterInfoName         = "cluster-info"
	clusterInfoConfigMapKey = "kubeconfig"
)

type execerController struct {
	credentialIssuerLocationConfig *CredentialIssuerLocationConfig
	credentialIssuerLabels         map[string]string
	discoveryURLOverride           *string
	dynamicCertProvider            dynamiccert.Provider
	podCommandExecutor             PodCommandExecutor
	clock                          clock.Clock
	pinnipedAPIClient              pinnipedclientset.Interface
	agentPodInformer               corev1informers.PodInformer
	configMapInformer              corev1informers.ConfigMapInformer
}

// NewExecerController returns a controllerlib.Controller that listens for agent pods with proper
// cert/key path annotations and execs into them to get the cert/key material. It sets the retrieved
// key material in a provided dynamicCertProvider.
//
// It also is tasked with updating the CredentialIssuer, located via the provided
// credentialIssuerLocationConfig, with any errors that it encounters.
func NewExecerController(
	credentialIssuerLocationConfig *CredentialIssuerLocationConfig,
	credentialIssuerLabels map[string]string,
	discoveryURLOverride *string,
	dynamicCertProvider dynamiccert.Provider,
	podCommandExecutor PodCommandExecutor,
	pinnipedAPIClient pinnipedclientset.Interface,
	clock clock.Clock,
	agentPodInformer corev1informers.PodInformer,
	configMapInformer corev1informers.ConfigMapInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "kube-cert-agent-execer-controller",
			Syncer: &execerController{
				credentialIssuerLocationConfig: credentialIssuerLocationConfig,
				credentialIssuerLabels:         credentialIssuerLabels,
				discoveryURLOverride:           discoveryURLOverride,
				dynamicCertProvider:            dynamicCertProvider,
				podCommandExecutor:             podCommandExecutor,
				pinnipedAPIClient:              pinnipedAPIClient,
				clock:                          clock,
				agentPodInformer:               agentPodInformer,
				configMapInformer:              configMapInformer,
			},
		},
		withInformer(
			agentPodInformer,
			pinnipedcontroller.SimpleFilter(isAgentPod, nil), // nil parent func is fine because each event is distinct
			controllerlib.InformerOption{},
		),
		withInformer(
			configMapInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(clusterInfoName, ClusterInfoNamespace),
			controllerlib.InformerOption{},
		),
	)
}

func (c *execerController) Sync(ctx controllerlib.Context) error {
	maybeAgentPod, err := c.agentPodInformer.Lister().Pods(ctx.Key.Namespace).Get(ctx.Key.Name)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s/%s pod: %w", ctx.Key.Namespace, ctx.Key.Name, err)
	}
	if notFound {
		// The pod in question does not exist, so it was probably deleted
		return nil
	}

	certPath, keyPath := c.getKeypairFilePaths(maybeAgentPod)
	if certPath == "" || keyPath == "" {
		// The annotator controller has not annotated this agent pod yet, or it is not an agent pod at all
		return nil
	}
	agentPod := maybeAgentPod

	if agentPod.Status.Phase != v1.PodRunning {
		// Seems to be an agent pod, but it is not ready yet
		return nil
	}

	certPEM, err := c.podCommandExecutor.Exec(agentPod.Namespace, agentPod.Name, "cat", certPath)
	if err != nil {
		strategyResultUpdateErr := issuerconfig.UpdateStrategy(
			ctx.Context,
			c.credentialIssuerLocationConfig.Name,
			c.credentialIssuerLabels,
			c.pinnipedAPIClient,
			strategyError(c.clock, err),
		)
		klog.ErrorS(strategyResultUpdateErr, "could not create or update CredentialIssuer with strategy success")
		return err
	}

	keyPEM, err := c.podCommandExecutor.Exec(agentPod.Namespace, agentPod.Name, "cat", keyPath)
	if err != nil {
		strategyResultUpdateErr := issuerconfig.UpdateStrategy(
			ctx.Context,
			c.credentialIssuerLocationConfig.Name,
			c.credentialIssuerLabels,
			c.pinnipedAPIClient,
			strategyError(c.clock, err),
		)
		klog.ErrorS(strategyResultUpdateErr, "could not create or update CredentialIssuer with strategy success")
		return err
	}

	c.dynamicCertProvider.Set([]byte(certPEM), []byte(keyPEM))

	apiInfo, err := c.getTokenCredentialRequestAPIInfo()
	if err != nil {
		strategyResultUpdateErr := issuerconfig.UpdateStrategy(
			ctx.Context,
			c.credentialIssuerLocationConfig.Name,
			c.credentialIssuerLabels,
			c.pinnipedAPIClient,
			configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.ErrorStrategyStatus,
				Reason:         configv1alpha1.CouldNotGetClusterInfoStrategyReason,
				Message:        err.Error(),
				LastUpdateTime: metav1.NewTime(c.clock.Now()),
			},
		)
		klog.ErrorS(strategyResultUpdateErr, "could not create or update CredentialIssuer with strategy success")
		return err
	}

	return issuerconfig.UpdateStrategy(
		ctx.Context,
		c.credentialIssuerLocationConfig.Name,
		c.credentialIssuerLabels,
		c.pinnipedAPIClient,
		configv1alpha1.CredentialIssuerStrategy{
			Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
			Status:         configv1alpha1.SuccessStrategyStatus,
			Reason:         configv1alpha1.FetchedKeyStrategyReason,
			Message:        "Key was fetched successfully",
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
			Frontend: &configv1alpha1.CredentialIssuerFrontend{
				Type:                          configv1alpha1.TokenCredentialRequestAPIFrontendType,
				TokenCredentialRequestAPIInfo: apiInfo,
			},
		},
	)
}

func (c *execerController) getTokenCredentialRequestAPIInfo() (*configv1alpha1.TokenCredentialRequestAPIInfo, error) {
	configMap, err := c.configMapInformer.
		Lister().
		ConfigMaps(ClusterInfoNamespace).
		Get(clusterInfoName)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s configmap: %w", clusterInfoName, err)
	}

	kubeConfigYAML, kubeConfigPresent := configMap.Data[clusterInfoConfigMapKey]
	if !kubeConfigPresent {
		return nil, fmt.Errorf("failed to get %s key from %s configmap", clusterInfoConfigMapKey, clusterInfoName)
	}

	kubeconfig, err := clientcmd.Load([]byte(kubeConfigYAML))
	if err != nil {
		return nil, fmt.Errorf("failed to load data from %s key in %s configmap", clusterInfoConfigMapKey, clusterInfoName)
	}

	for _, v := range kubeconfig.Clusters {
		result := &configv1alpha1.TokenCredentialRequestAPIInfo{
			Server:                   v.Server,
			CertificateAuthorityData: base64.StdEncoding.EncodeToString(v.CertificateAuthorityData),
		}
		if c.discoveryURLOverride != nil {
			result.Server = *c.discoveryURLOverride
		}
		return result, nil
	}
	return nil, fmt.Errorf("kubeconfig in %s key in %s configmap did not contain any clusters", clusterInfoConfigMapKey, clusterInfoName)
}

func (c *execerController) getKeypairFilePaths(pod *v1.Pod) (string, string) {
	annotations := pod.Annotations
	if annotations == nil {
		annotations = make(map[string]string)
	}

	certPath := annotations[agentPodCertPathAnnotationKey]
	keyPath := annotations[agentPodKeyPathAnnotationKey]

	return certPath, keyPath
}
