// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"context"
	"fmt"

	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/clock"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	pinnipedclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/issuerconfig"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

// These constants are the default values for the kube-controller-manager flags. If the flags are
// not properly set on the kube-controller-manager process, then we will fallback to using these.
const (
	k8sAPIServerCACertPEMDefaultPath = "/etc/kubernetes/ca/ca.pem"
	k8sAPIServerCAKeyPEMDefaultPath  = "/etc/kubernetes/ca/ca.key"
)

type annotaterController struct {
	agentPodConfig                 *AgentPodConfig
	credentialIssuerLocationConfig *CredentialIssuerLocationConfig
	credentialIssuerLabels         map[string]string
	clock                          clock.Clock
	k8sClient                      kubernetes.Interface
	pinnipedAPIClient              pinnipedclientset.Interface
	kubeSystemPodInformer          corev1informers.PodInformer
	agentPodInformer               corev1informers.PodInformer
}

// NewAnnotaterController returns a controller that updates agent pods with the path to the kube
// API's certificate and key.
//
// This controller will add annotations to agent pods with the best-guess paths to the kube API's
// certificate and key.
//
// It also is tasked with updating the CredentialIssuer, located via the provided
// credentialIssuerLocationConfig, with any errors that it encounters.
func NewAnnotaterController(
	agentPodConfig *AgentPodConfig,
	credentialIssuerLocationConfig *CredentialIssuerLocationConfig,
	credentialIssuerLabels map[string]string,
	clock clock.Clock,
	k8sClient kubernetes.Interface,
	pinnipedAPIClient pinnipedclientset.Interface,
	kubeSystemPodInformer corev1informers.PodInformer,
	agentPodInformer corev1informers.PodInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "kube-cert-agent-annotater-controller",
			Syncer: &annotaterController{
				agentPodConfig:                 agentPodConfig,
				credentialIssuerLocationConfig: credentialIssuerLocationConfig,
				credentialIssuerLabels:         credentialIssuerLabels,
				clock:                          clock,
				k8sClient:                      k8sClient,
				pinnipedAPIClient:              pinnipedAPIClient,
				kubeSystemPodInformer:          kubeSystemPodInformer,
				agentPodInformer:               agentPodInformer,
			},
		},
		withInformer(
			kubeSystemPodInformer,
			pinnipedcontroller.SimpleFilterWithSingletonQueue(isControllerManagerPod),
			controllerlib.InformerOption{},
		),
		withInformer(
			agentPodInformer,
			pinnipedcontroller.SimpleFilterWithSingletonQueue(isAgentPod),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *annotaterController) Sync(ctx controllerlib.Context) error {
	agentPods, err := c.agentPodInformer.
		Lister().
		Pods(c.agentPodConfig.Namespace).
		List(c.agentPodConfig.AgentSelector())
	if err != nil {
		return fmt.Errorf("informer cannot list agent pods: %w", err)
	}

	for _, agentPod := range agentPods {
		controllerManagerPod, err := findControllerManagerPodForSpecificAgentPod(agentPod, c.kubeSystemPodInformer)
		if err != nil {
			return err
		}
		if controllerManagerPod == nil {
			// The deleter will clean this orphaned agent.
			continue
		}

		certPath := getContainerArgByName(
			controllerManagerPod,
			"cluster-signing-cert-file",
			k8sAPIServerCACertPEMDefaultPath,
		)
		keyPath := getContainerArgByName(
			controllerManagerPod,
			"cluster-signing-key-file",
			k8sAPIServerCAKeyPEMDefaultPath,
		)
		if err := c.maybeUpdateAgentPod(
			ctx.Context,
			agentPod.Name,
			agentPod.Namespace,
			certPath,
			keyPath,
		); err != nil {
			err = fmt.Errorf("cannot update agent pod: %w", err)
			strategyResultUpdateErr := issuerconfig.UpdateStrategy(
				ctx.Context,
				c.credentialIssuerLocationConfig.Name,
				c.credentialIssuerLabels,
				c.pinnipedAPIClient,
				strategyError(c.clock, err),
			)
			if strategyResultUpdateErr != nil {
				// If the CI update fails, then we probably want to try again. This controller will get
				// called again because of the pod create failure, so just try the CI update again then.
				klog.ErrorS(strategyResultUpdateErr, "could not create or update CredentialIssuer")
			}

			return err
		}
	}

	return nil
}

func (c *annotaterController) maybeUpdateAgentPod(
	ctx context.Context,
	name string,
	namespace string,
	certPath string,
	keyPath string,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		agentPod, err := c.k8sClient.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if agentPod.Annotations[agentPodCertPathAnnotationKey] != certPath ||
			agentPod.Annotations[agentPodKeyPathAnnotationKey] != keyPath {
			if err := c.reallyUpdateAgentPod(
				ctx,
				agentPod,
				certPath,
				keyPath,
			); err != nil {
				return err
			}
		}

		return nil
	})
}

func (c *annotaterController) reallyUpdateAgentPod(
	ctx context.Context,
	agentPod *corev1.Pod,
	certPath string,
	keyPath string,
) error {
	// Create a deep copy of the agent pod since it is coming straight from the cache.
	updatedAgentPod := agentPod.DeepCopy()
	if updatedAgentPod.Annotations == nil {
		updatedAgentPod.Annotations = make(map[string]string)
	}
	updatedAgentPod.Annotations[agentPodCertPathAnnotationKey] = certPath
	updatedAgentPod.Annotations[agentPodKeyPathAnnotationKey] = keyPath

	plog.Debug(
		"updating agent pod annotations",
		"pod",
		klog.KObj(updatedAgentPod),
		"certPath",
		certPath,
		"keyPath",
		keyPath,
	)
	_, err := c.k8sClient.
		CoreV1().
		Pods(agentPod.Namespace).
		Update(ctx, updatedAgentPod, metav1.UpdateOptions{})
	return err
}

func getContainerArgByName(pod *corev1.Pod, name, fallbackValue string) string {
	for _, container := range pod.Spec.Containers {
		flagset := pflag.NewFlagSet("", pflag.ContinueOnError)
		flagset.ParseErrorsWhitelist = pflag.ParseErrorsWhitelist{UnknownFlags: true}
		var val string
		flagset.StringVar(&val, name, "", "")
		_ = flagset.Parse(append(container.Command, container.Args...))
		if val != "" {
			return val
		}
	}
	return fallbackValue
}
