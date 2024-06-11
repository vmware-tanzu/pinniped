// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"fmt"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/klog/v2"

	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/kubeclient"
)

// NewLegacyPodCleanerController returns a controller that cleans up legacy kube-cert-agent Pods created by Pinniped v0.7.0 and below.
func NewLegacyPodCleanerController(
	cfg AgentConfig,
	client *kubeclient.Client,
	agentPods corev1informers.PodInformer,
	log logr.Logger,
) controllerlib.Controller {
	// legacyAgentLabels are the Kubernetes labels we previously added to agent pods (the new value is "v2").
	// We also expect these pods to have the "extra" labels configured on the Concierge.
	legacyAgentLabels := map[string]string{"kube-cert-agent.pinniped.dev": "true"}
	for k, v := range cfg.Labels {
		legacyAgentLabels[k] = v
	}
	legacyAgentSelector := labels.SelectorFromSet(legacyAgentLabels)

	log = log.WithName("legacy-pod-cleaner-controller")

	return controllerlib.New(
		controllerlib.Config{
			Name: "legacy-pod-cleaner-controller",
			Syncer: controllerlib.SyncFunc(func(ctx controllerlib.Context) error {
				podClient := client.Kubernetes.CoreV1().Pods(ctx.Key.Namespace)

				// avoid blind writes to the API
				agentPod, err := podClient.Get(ctx.Context, ctx.Key.Name, metav1.GetOptions{})
				if err != nil {
					if apierrors.IsNotFound(err) {
						return nil
					}
					return fmt.Errorf("could not get legacy agent pod: %w", err)
				}

				if err := podClient.Delete(ctx.Context, ctx.Key.Name, metav1.DeleteOptions{
					Preconditions: &metav1.Preconditions{
						UID:             &agentPod.UID,
						ResourceVersion: &agentPod.ResourceVersion,
					},
				}); err != nil {
					if apierrors.IsNotFound(err) {
						return nil
					}
					return fmt.Errorf("could not delete legacy agent pod: %w", err)
				}

				log.Info("deleted legacy kube-cert-agent pod", "pod", klog.KRef(ctx.Key.Namespace, ctx.Key.Name))
				return nil
			}),
		},
		controllerlib.WithInformer(
			agentPods,
			pinnipedcontroller.SimpleFilter(func(obj metav1.Object) bool {
				return obj.GetNamespace() == cfg.Namespace && legacyAgentSelector.Matches(labels.Set(obj.GetLabels()))
			}, nil),
			controllerlib.InformerOption{},
		),
	)
}
