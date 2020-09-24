// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"testing"

	"github.com/sclevine/spec"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubeinformers "k8s.io/client-go/informers"
	corev1informers "k8s.io/client-go/informers/core/v1"

	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func exampleControllerManagerAndAgentPods(
	kubeSystemNamespace,
	agentPodNamespace,
	certPath,
	keyPath string,
) (*corev1.Pod, *corev1.Pod) {
	controllerManagerPod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: corev1.SchemeGroupVersion.String(),
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: kubeSystemNamespace,
			Name:      "some-controller-manager-name",
			Labels: map[string]string{
				"component": "kube-controller-manager",
			},
			UID: types.UID("some-controller-manager-uid"),
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Image: "some-controller-manager-image",
					Command: []string{
						"kube-controller-manager",
						"--cluster-signing-cert-file=" + certPath,
						"--cluster-signing-key-file=" + keyPath,
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name: "some-volume-mount-name",
						},
					},
				},
			},
			NodeName: "some-node-name",
			NodeSelector: map[string]string{
				"some-node-selector-key": "some-node-selector-value",
			},
			Tolerations: []corev1.Toleration{
				{
					Key: "some-toleration",
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	zero := int64(0)

	// fnv 32a hash of controller-manager uid
	controllerManagerPodHash := "fbb0addd"
	agentPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "some-agent-name-" + controllerManagerPodHash,
			Namespace: agentPodNamespace,
			Labels: map[string]string{
				"kube-cert-agent.pinniped.dev": "true",
			},
			Annotations: map[string]string{
				"kube-cert-agent.pinniped.dev/controller-manager-name": controllerManagerPod.Name,
				"kube-cert-agent.pinniped.dev/controller-manager-uid":  string(controllerManagerPod.UID),
			},
		},
		Spec: corev1.PodSpec{
			TerminationGracePeriodSeconds: &zero,
			ImagePullSecrets: []corev1.LocalObjectReference{
				{
					Name: "some-image-pull-secret",
				},
			},
			Containers: []corev1.Container{
				{
					Name:            "sleeper",
					Image:           "some-agent-image",
					ImagePullPolicy: corev1.PullIfNotPresent,
					VolumeMounts:    controllerManagerPod.Spec.Containers[0].VolumeMounts,
					Command:         []string{"/bin/sleep", "infinity"},
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("16Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("16Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
					},
				},
			},
			RestartPolicy:                corev1.RestartPolicyNever,
			AutomountServiceAccountToken: boolPtr(false),
			NodeName:                     controllerManagerPod.Spec.NodeName,
			NodeSelector:                 controllerManagerPod.Spec.NodeSelector,
			Tolerations:                  controllerManagerPod.Spec.Tolerations,
		},
	}

	return controllerManagerPod, agentPod
}

func defineSharedKubecertagentFilterSpecs(
	t *testing.T,
	name string,
	newFunc func(
		agentPodConfig *AgentPodConfig,
		credentialIssuerConfigLocationConfig *CredentialIssuerConfigLocationConfig,
		kubeSystemPodInformer corev1informers.PodInformer,
		agentPodInformer corev1informers.PodInformer,
		observableWithInformerOption *testutil.ObservableWithInformerOption,
	),
) {
	spec.Run(t, name, func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var kubeSystemPodInformerFilter, agentPodInformerFilter controllerlib.Filter

		whateverPod := &corev1.Pod{}

		it.Before(func() {
			r = require.New(t)

			kubeSystemPodInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().Pods()
			agentPodInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().Pods()
			observableWithInformerOption := testutil.NewObservableWithInformerOption()
			newFunc(&AgentPodConfig{}, &CredentialIssuerConfigLocationConfig{}, kubeSystemPodInformer, agentPodInformer, observableWithInformerOption)

			kubeSystemPodInformerFilter = observableWithInformerOption.GetFilterForInformer(kubeSystemPodInformer)
			agentPodInformerFilter = observableWithInformerOption.GetFilterForInformer(agentPodInformer)
		})

		when("the event is happening in the kube system namespace", func() {
			when("a pod with the proper controller manager labels and phase is added/updated/deleted", func() {
				it("returns true", func() {
					pod := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"component": "kube-controller-manager",
							},
						},
						Status: corev1.PodStatus{
							Phase: corev1.PodRunning,
						},
					}

					r.True(kubeSystemPodInformerFilter.Add(pod))
					r.True(kubeSystemPodInformerFilter.Update(whateverPod, pod))
					r.True(kubeSystemPodInformerFilter.Update(pod, whateverPod))
					r.True(kubeSystemPodInformerFilter.Delete(pod))
				})
			})

			when("a pod without the proper controller manager label is added/updated/deleted", func() {
				it("returns false", func() {
					pod := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{},
						Status: corev1.PodStatus{
							Phase: corev1.PodRunning,
						},
					}

					r.False(kubeSystemPodInformerFilter.Add(pod))
					r.False(kubeSystemPodInformerFilter.Update(whateverPod, pod))
					r.False(kubeSystemPodInformerFilter.Update(pod, whateverPod))
					r.False(kubeSystemPodInformerFilter.Delete(pod))
				})
			})

			when("a pod without the proper controller manager phase is added/updated/deleted", func() {
				it("returns false", func() {
					pod := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"component": "kube-controller-manager",
							},
						},
					}

					r.False(kubeSystemPodInformerFilter.Add(pod))
					r.False(kubeSystemPodInformerFilter.Update(whateverPod, pod))
					r.False(kubeSystemPodInformerFilter.Update(pod, whateverPod))
					r.False(kubeSystemPodInformerFilter.Delete(pod))
				})
			})
		})

		when("the change is happening in the agent's informer", func() {
			when("a pod with the agent label is added/updated/deleted", func() {
				it("returns true", func() {
					pod := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"kube-cert-agent.pinniped.dev": "true",
							},
						},
					}

					r.True(agentPodInformerFilter.Add(pod))
					r.True(agentPodInformerFilter.Update(whateverPod, pod))
					r.True(agentPodInformerFilter.Update(pod, whateverPod))
					r.True(agentPodInformerFilter.Delete(pod))
				})
			})

			when("a pod missing the agent label is added/updated/deleted", func() {
				it("returns false", func() {
					pod := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"some-other-label-key": "some-other-label-value",
							},
						},
					}

					r.False(agentPodInformerFilter.Add(pod))
					r.False(agentPodInformerFilter.Update(whateverPod, pod))
					r.False(agentPodInformerFilter.Update(pod, whateverPod))
					r.False(agentPodInformerFilter.Delete(pod))
				})
			})
		})
	})
}
