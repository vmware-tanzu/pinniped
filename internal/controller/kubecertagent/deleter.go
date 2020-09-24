// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
)

type deleterController struct {
	agentPodConfig        *AgentPodConfig
	k8sClient             kubernetes.Interface
	kubeSystemPodInformer corev1informers.PodInformer
	agentPodInformer      corev1informers.PodInformer
}

// NewDeleterController returns a controller that deletes any kube-cert-agent pods that are out of
// sync with the known kube-controller-manager pods.
//
// This controller only uses the Template field of the provided agentInfo.
func NewDeleterController(
	agentPodConfig *AgentPodConfig,
	k8sClient kubernetes.Interface,
	kubeSystemPodInformer corev1informers.PodInformer,
	agentPodInformer corev1informers.PodInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "kube-cert-agent-deleter-controller",
			Syncer: &deleterController{
				agentPodConfig:        agentPodConfig,
				k8sClient:             k8sClient,
				kubeSystemPodInformer: kubeSystemPodInformer,
				agentPodInformer:      agentPodInformer,
			},
		},
		withInformer(
			kubeSystemPodInformer,
			pinnipedcontroller.SimpleFilter(isControllerManagerPod),
			controllerlib.InformerOption{},
		),
		withInformer(
			agentPodInformer,
			pinnipedcontroller.SimpleFilter(isAgentPod),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *deleterController) Sync(ctx controllerlib.Context) error {
	agentSelector := labels.SelectorFromSet(c.agentPodConfig.Labels())
	agentPods, err := c.agentPodInformer.
		Lister().
		Pods(c.agentPodConfig.Namespace).
		List(agentSelector)
	if err != nil {
		return fmt.Errorf("informer cannot list agent pods: %w", err)
	}

	for _, agentPod := range agentPods {
		controllerManagerPod, err := findControllerManagerPodForSpecificAgentPod(agentPod, c.kubeSystemPodInformer)
		if err != nil {
			return err
		}
		if controllerManagerPod == nil ||
			!isAgentPodUpToDate(agentPod, newAgentPod(controllerManagerPod, c.agentPodConfig.PodTemplate())) {
			klog.InfoS("deleting agent pod", "pod", klog.KObj(agentPod))
			err := c.k8sClient.
				CoreV1().
				Pods(agentPod.Namespace).
				Delete(ctx.Context, agentPod.Name, metav1.DeleteOptions{})
			if err != nil {
				return fmt.Errorf("cannot delete agent pod: %w", err)
			}
		}
	}

	return nil
}
