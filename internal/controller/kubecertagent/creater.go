// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
)

type createrController struct {
	agentInfo             *Info
	k8sClient             kubernetes.Interface
	kubeSystemPodInformer corev1informers.PodInformer
	agentPodInformer      corev1informers.PodInformer
}

// NewCreaterController returns a controller that creates new kube-cert-agent pods for every known
// kube-controller-manager pod.
//
// This controller only uses the Template field of the provided agentInfo.
func NewCreaterController(
	agentInfo *Info,
	k8sClient kubernetes.Interface,
	kubeSystemPodInformer corev1informers.PodInformer,
	agentPodInformer corev1informers.PodInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			//nolint: misspell
			Name: "kube-cert-agent-creater-controller",
			Syncer: &createrController{
				agentInfo:             agentInfo,
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
			pinnipedcontroller.SimpleFilter(func(obj metav1.Object) bool {
				return isAgentPod(obj, agentInfo.Template.Labels)
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

	controllerManagerPods, err := c.kubeSystemPodInformer.Lister().List(controllerManagerSelector)
	if err != nil {
		return fmt.Errorf("informer cannot list controller manager pods: %w", err)
	}

	// TODO if controllerManagerPods is empty then update the CIC status with an error message saying that they couldn't be found

	for _, controllerManagerPod := range controllerManagerPods {
		agentPod, err := findAgentPodForSpecificControllerManagerPod(
			controllerManagerPod,
			c.kubeSystemPodInformer,
			c.agentPodInformer,
			c.agentInfo.Template.Labels,
		)
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
				Pods(c.agentInfo.Template.Namespace).
				Create(ctx.Context, agentPod, metav1.CreateOptions{})
			if err != nil {
				// TODO if agent pods fail to create then update the CIC status with an error saying that they couldn't create
				return fmt.Errorf("cannot create agent pod: %w", err)
			}
		}

		// The deleter controller handles the case where the expected fields do not match in the agent pod.
	}

	return nil
}

func findAgentPodForSpecificControllerManagerPod(
	controllerManagerPod *corev1.Pod,
	kubeSystemPodInformer corev1informers.PodInformer,
	agentPodInformer corev1informers.PodInformer,
	agentLabels map[string]string,
) (*corev1.Pod, error) {
	agentSelector := labels.SelectorFromSet(agentLabels)
	agentPods, err := agentPodInformer.
		Lister().
		List(agentSelector)
	if err != nil {
		return nil, fmt.Errorf("informer cannot list agent pods: %w", err)
	}

	for _, maybeAgentPod := range agentPods {
		maybeControllerManagerPod, err := findControllerManagerPodForSpecificAgentPod(
			maybeAgentPod,
			kubeSystemPodInformer,
		)
		if err != nil {
			return nil, err
		}
		if maybeControllerManagerPod != nil &&
			maybeControllerManagerPod.UID == controllerManagerPod.UID {
			return maybeAgentPod, nil
		}
	}

	return nil, nil
}
