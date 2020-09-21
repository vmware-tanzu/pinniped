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

type createrController struct {
	agentInfo   *Info
	k8sClient   kubernetes.Interface
	podInformer corev1informers.PodInformer
}

// NewCreaterController returns a controller that creates new kube-cert-agent pods for every known
// kube-controller-manager pod.
//
// This controller only uses the Template field of the provided agentInfo.
func NewCreaterController(
	agentInfo *Info,
	k8sClient kubernetes.Interface,
	podInformer corev1informers.PodInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			//nolint: misspell
			Name: "kube-cert-agent-creater-controller",
			Syncer: &createrController{
				agentInfo:   agentInfo,
				k8sClient:   k8sClient,
				podInformer: podInformer,
			},
		},
		withInformer(
			podInformer,
			pinnipedcontroller.SimpleFilter(func(obj metav1.Object) bool {
				return isControllerManagerPod(obj) || isAgentPod(obj, agentInfo.Template.Labels)
			}),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *createrController) Sync(ctx controllerlib.Context) error {
	controllerManagerSelector, err := labels.Parse("component=kube-controller-manager")
	if err != nil {
		return fmt.Errorf("cannot create controller manager selector: %w", err)
	}

	controllerManagerPods, err := c.podInformer.Lister().List(controllerManagerSelector)
	if err != nil {
		return fmt.Errorf("informer cannot list controller manager pods: %w", err)
	}

	for _, controllerManagerPod := range controllerManagerPods {
		agentPod, err := findAgentPod(controllerManagerPod, c.podInformer, c.agentInfo.Template.Labels)
		if err != nil {
			return err
		}
		if agentPod == nil {
			agentPod = newAgentPod(controllerManagerPod, c.agentInfo.Template)

			klog.InfoS(
				"creating agent pod",
				"pod",
				klog.KObj(agentPod),
				"controller",
				klog.KObj(controllerManagerPod),
			)
			_, err := c.k8sClient.CoreV1().
				Pods(ControllerManagerNamespace).
				Create(ctx.Context, agentPod, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("cannot create agent pod: %w", err)
			}
		}

		// The deleter controller handles the case where the expected fields do not match in the agent
		// pod.
	}

	return nil
}
