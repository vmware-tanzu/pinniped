// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

type deleterController struct {
	agentPodConfig        *AgentPodConfig
	k8sClient             kubernetes.Interface
	kubeSystemPodInformer corev1informers.PodInformer
	agentPodInformer      corev1informers.PodInformer
}

// NewDeleterController returns a controller that deletes any kube-cert-agent pods that are out of
// sync with the known kube-controller-manager pods.
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
func (c *deleterController) Sync(ctx controllerlib.Context) error {
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
		if controllerManagerPod == nil || inTerminalState(agentPod) ||
			!isAgentPodUpToDate(agentPod, c.agentPodConfig.newAgentPod(controllerManagerPod)) {
			plog.Debug("deleting agent pod", "pod", klog.KObj(agentPod))
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

func inTerminalState(pod *corev1.Pod) bool {
	switch pod.Status.Phase {
	// Running and Pending are non-terminal states. We should not delete pods in these states.
	case corev1.PodRunning, corev1.PodPending:
		return false

	// Succeeded and Failed are terminal states. If a pod has entered one of these states, we want to delete it so
	// it can be recreated by the other controllers.
	case corev1.PodSucceeded, corev1.PodFailed:
		return true

	// In other cases, we want to delete the pod but more carefully. We only consider the pod "terminal" if it is in
	// this state more than 5 minutes after creation.
	case corev1.PodUnknown:
		fallthrough
	default:
		return time.Since(pod.CreationTimestamp.Time) > 5*time.Minute
	}
}
