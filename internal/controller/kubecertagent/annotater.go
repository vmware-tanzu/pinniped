// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"context"
	"fmt"

	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
)

type annotaterController struct {
	agentInfo             *Info
	k8sClient             kubernetes.Interface
	kubeSystemPodInformer corev1informers.PodInformer
	agentPodInformer      corev1informers.PodInformer
}

// NewAnnotaterController returns a controller that updates agent pods with the path to the kube
// API's certificate and key.
//
// This controller will add annotations to agent pods, using the provided
// agentInfo.CertPathAnnotation and agentInfo.KeyPathAnnotation annotation keys, with the best-guess
// paths to the kube API's certificate and key.
func NewAnnotaterController(
	agentInfo *Info,
	k8sClient kubernetes.Interface,
	kubeSystemPodInformer corev1informers.PodInformer,
	agentPodInformer corev1informers.PodInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "kube-cert-agent-annotater-controller",
			Syncer: &annotaterController{
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
func (c *annotaterController) Sync(ctx controllerlib.Context) error {
	agentSelector := labels.SelectorFromSet(c.agentInfo.Template.Labels)
	agentPods, err := c.agentPodInformer.
		Lister().
		Pods(c.agentInfo.Template.Namespace).
		List(agentSelector)
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

		certPath, certPathOK := getContainerArgByName(controllerManagerPod, "cluster-signing-cert-file")
		keyPath, keyPathOK := getContainerArgByName(controllerManagerPod, "cluster-signing-key-file")
		if err := c.maybeUpdateAgentPod(
			ctx.Context,
			agentPod.Name,
			agentPod.Namespace,
			certPath,
			certPathOK,
			keyPath,
			keyPathOK,
		); err != nil {
			return fmt.Errorf("cannot update agent pod: %w", err)
		}
	}

	return nil
}

func (c *annotaterController) maybeUpdateAgentPod(
	ctx context.Context,
	name string,
	namespace string,
	certPath string,
	certPathOK bool,
	keyPath string,
	keyPathOK bool,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		agentPod, err := c.agentPodInformer.Lister().Pods(namespace).Get(name)
		if err != nil {
			return err
		}

		if (certPathOK && agentPod.Annotations[c.agentInfo.CertPathAnnotation] != certPath) ||
			(keyPathOK && agentPod.Annotations[c.agentInfo.KeyPathAnnotation] != keyPath) {
			if err := c.reallyUpdateAgentPod(
				ctx,
				agentPod,
				certPath,
				certPathOK,
				keyPath,
				keyPathOK,
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
	certPathOK bool,
	keyPath string,
	keyPathOK bool,
) error {
	// Create a deep copy of the agent pod since it is coming straight from the cache.
	updatedAgentPod := agentPod.DeepCopy()
	if updatedAgentPod.Annotations == nil {
		updatedAgentPod.Annotations = make(map[string]string)
	}
	if certPathOK {
		updatedAgentPod.Annotations[c.agentInfo.CertPathAnnotation] = certPath
	}
	if keyPathOK {
		updatedAgentPod.Annotations[c.agentInfo.KeyPathAnnotation] = keyPath
	}

	klog.InfoS(
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

func getContainerArgByName(pod *corev1.Pod, name string) (string, bool) {
	for _, container := range pod.Spec.Containers {
		flagset := pflag.NewFlagSet("", pflag.ContinueOnError)
		flagset.ParseErrorsWhitelist = pflag.ParseErrorsWhitelist{UnknownFlags: true}
		var val string
		flagset.StringVar(&val, name, "", "")
		_ = flagset.Parse(append(container.Command, container.Args...))
		if val != "" {
			return val, true
		}
	}
	return "", false
}
