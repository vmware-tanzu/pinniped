// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"testing"

	"github.com/sclevine/spec"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	corev1informers "k8s.io/client-go/informers/core/v1"

	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func runFilterTest(
	t *testing.T,
	name string,
	newFunc func(
		agentPodTemplate *corev1.Pod,
		podsInformer corev1informers.PodInformer,
		observableWithInformerOption *testutil.ObservableWithInformerOption,
	),
) {
	spec.Run(t, name, func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var subject controllerlib.Filter

		whateverPod := &corev1.Pod{}

		it.Before(func() {
			r = require.New(t)

			agentPodTemplate := &corev1.Pod{}
			agentPodTemplate.Labels = map[string]string{
				"some-label-key":       "some-label-value",
				"some-other-label-key": "some-other-label-value",
			}
			podsInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().Pods()
			observableWithInformerOption := testutil.NewObservableWithInformerOption()
			newFunc(agentPodTemplate, podsInformer, observableWithInformerOption)

			subject = observableWithInformerOption.GetFilterForInformer(podsInformer)
		})

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

				r.True(subject.Add(pod))
				r.True(subject.Update(whateverPod, pod))
				r.True(subject.Update(pod, whateverPod))
				r.True(subject.Delete(pod))
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

				r.False(subject.Add(pod))
				r.False(subject.Update(whateverPod, pod))
				r.False(subject.Update(pod, whateverPod))
				r.False(subject.Delete(pod))
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

				r.False(subject.Add(pod))
				r.False(subject.Update(whateverPod, pod))
				r.False(subject.Update(pod, whateverPod))
				r.False(subject.Delete(pod))
			})
		})

		when("a pod with all the agent labels is added/updated/deleted", func() {
			it("returns true", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"some-label-key":       "some-label-value",
							"some-other-label-key": "some-other-label-value",
						},
					},
				}

				r.True(subject.Add(pod))
				r.True(subject.Update(whateverPod, pod))
				r.True(subject.Update(pod, whateverPod))
				r.True(subject.Delete(pod))
			})
		})

		when("a pod missing one of the agent labels is added/updated/deleted", func() {
			it("returns false", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"some-other-label-key": "some-other-label-value",
						},
					},
				}

				r.False(subject.Add(pod))
				r.False(subject.Update(whateverPod, pod))
				r.False(subject.Update(pod, whateverPod))
				r.False(subject.Delete(pod))
			})
		})
	})
}
