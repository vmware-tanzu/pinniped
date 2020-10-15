// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/clock"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/klog/v2"

	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/dynamiccert"
)

type execerController struct {
	credentialIssuerConfigLocationConfig *CredentialIssuerConfigLocationConfig
	dynamicCertProvider                  dynamiccert.Provider
	podCommandExecutor                   PodCommandExecutor
	clock                                clock.Clock
	pinnipedAPIClient                    pinnipedclientset.Interface
	agentPodInformer                     corev1informers.PodInformer
}

// NewExecerController returns a controllerlib.Controller that listens for agent pods with proper
// cert/key path annotations and execs into them to get the cert/key material. It sets the retrieved
// key material in a provided dynamicCertProvider.
//
// It also is tasked with updating the CredentialIssuerConfig, located via the provided
// credentialIssuerConfigLocationConfig, with any errors that it encounters.
func NewExecerController(
	credentialIssuerConfigLocationConfig *CredentialIssuerConfigLocationConfig,
	dynamicCertProvider dynamiccert.Provider,
	podCommandExecutor PodCommandExecutor,
	pinnipedAPIClient pinnipedclientset.Interface,
	clock clock.Clock,
	agentPodInformer corev1informers.PodInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "kube-cert-agent-execer-controller",
			Syncer: &execerController{
				credentialIssuerConfigLocationConfig: credentialIssuerConfigLocationConfig,
				dynamicCertProvider:                  dynamicCertProvider,
				podCommandExecutor:                   podCommandExecutor,
				pinnipedAPIClient:                    pinnipedAPIClient,
				clock:                                clock,
				agentPodInformer:                     agentPodInformer,
			},
		},
		withInformer(
			agentPodInformer,
			pinnipedcontroller.SimpleFilter(isAgentPod),
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
		strategyResultUpdateErr := createOrUpdateCredentialIssuerConfig(ctx.Context, *c.credentialIssuerConfigLocationConfig, nil, c.clock, c.pinnipedAPIClient, err)
		klog.ErrorS(strategyResultUpdateErr, "could not create or update CredentialIssuerConfig with strategy success")
		return err
	}

	keyPEM, err := c.podCommandExecutor.Exec(agentPod.Namespace, agentPod.Name, "cat", keyPath)
	if err != nil {
		strategyResultUpdateErr := createOrUpdateCredentialIssuerConfig(ctx.Context, *c.credentialIssuerConfigLocationConfig, nil, c.clock, c.pinnipedAPIClient, err)
		klog.ErrorS(strategyResultUpdateErr, "could not create or update CredentialIssuerConfig with strategy success")
		return err
	}

	c.dynamicCertProvider.Set([]byte(certPEM), []byte(keyPEM))

	err = createOrUpdateCredentialIssuerConfig(ctx.Context, *c.credentialIssuerConfigLocationConfig, nil, c.clock, c.pinnipedAPIClient, nil)
	if err != nil {
		return err
	}

	return nil
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
