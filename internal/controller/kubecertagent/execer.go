// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/clock"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/klog/v2"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"
	"go.pinniped.dev/internal/certauthority/kubecertauthority"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/issuerconfig"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/provider"
)

type execerController struct {
	agentInfo                           *Info
	credentialIssuerConfigNamespaceName string
	credentialIssuerConfigResourceName  string
	dynamicCertProvider                 provider.DynamicTLSServingCertProvider
	podCommandExecutor                  kubecertauthority.PodCommandExecutor
	clock                               clock.Clock
	pinnipedAPIClient                   pinnipedclientset.Interface
	agentPodInformer                    corev1informers.PodInformer
}

func NewExecerController(
	agentInfo *Info,
	credentialIssuerConfigNamespaceName string,
	credentialIssuerConfigResourceName string,
	dynamicCertProvider provider.DynamicTLSServingCertProvider,
	podCommandExecutor kubecertauthority.PodCommandExecutor,
	pinnipedAPIClient pinnipedclientset.Interface,
	clock clock.Clock,
	agentPodInformer corev1informers.PodInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "kube-cert-agent-execer-controller",
			Syncer: &execerController{
				agentInfo:                           agentInfo,
				credentialIssuerConfigNamespaceName: credentialIssuerConfigNamespaceName,
				credentialIssuerConfigResourceName:  credentialIssuerConfigResourceName,
				dynamicCertProvider:                 dynamicCertProvider,
				podCommandExecutor:                  podCommandExecutor,
				pinnipedAPIClient:                   pinnipedAPIClient,
				clock:                               clock,
				agentPodInformer:                    agentPodInformer,
			},
		},
		withInformer(
			agentPodInformer,
			pinnipedcontroller.SimpleFilter(func(obj metav1.Object) bool {
				return isAgentPod(obj, agentInfo.Template.Labels)
			}),
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
		strategyResultUpdateErr := c.createOrUpdateCredentialIssuerConfig(ctx, c.strategyError(err))
		klog.ErrorS(strategyResultUpdateErr, "could not create or update CredentialIssuerConfig with strategy success")
		return err
	}

	keyPEM, err := c.podCommandExecutor.Exec(agentPod.Namespace, agentPod.Name, "cat", keyPath)
	if err != nil {
		strategyResultUpdateErr := c.createOrUpdateCredentialIssuerConfig(ctx, c.strategyError(err))
		klog.ErrorS(strategyResultUpdateErr, "could not create or update CredentialIssuerConfig with strategy success")
		return err
	}

	c.dynamicCertProvider.Set([]byte(certPEM), []byte(keyPEM))

	err = c.createOrUpdateCredentialIssuerConfig(ctx, c.strategySuccess())
	_ = err // TODO return this error? (needs test)

	return nil
}

func (c *execerController) createOrUpdateCredentialIssuerConfig(ctx controllerlib.Context, strategyResult configv1alpha1.CredentialIssuerConfigStrategy) error {
	return issuerconfig.CreateOrUpdateCredentialIssuerConfig(
		ctx.Context,
		c.credentialIssuerConfigNamespaceName,
		c.credentialIssuerConfigResourceName,
		c.pinnipedAPIClient,
		func(configToUpdate *configv1alpha1.CredentialIssuerConfig) {
			configToUpdate.Status.Strategies = []configv1alpha1.CredentialIssuerConfigStrategy{strategyResult}
		},
	)
}

func (c *execerController) strategySuccess() configv1alpha1.CredentialIssuerConfigStrategy {
	return configv1alpha1.CredentialIssuerConfigStrategy{
		Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
		Status:         configv1alpha1.SuccessStrategyStatus,
		Reason:         configv1alpha1.FetchedKeyStrategyReason,
		Message:        "Key was fetched successfully",
		LastUpdateTime: metav1.NewTime(c.clock.Now()),
	}
}

func (c *execerController) strategyError(err error) configv1alpha1.CredentialIssuerConfigStrategy {
	return configv1alpha1.CredentialIssuerConfigStrategy{
		Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
		Status:         configv1alpha1.ErrorStrategyStatus,
		Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
		Message:        err.Error(),
		LastUpdateTime: metav1.NewTime(c.clock.Now()),
	}
}

func (c *execerController) getKeypairFilePaths(pod *v1.Pod) (string, string) {
	annotations := pod.Annotations
	if annotations == nil {
		annotations = make(map[string]string)
	}

	certPath := annotations[c.agentInfo.CertPathAnnotation]
	keyPath := annotations[c.agentInfo.KeyPathAnnotation]

	return certPath, keyPath
}
