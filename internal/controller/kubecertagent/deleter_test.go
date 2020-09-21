// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"context"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kubeinformers "k8s.io/client-go/informers"
	corev1informers "k8s.io/client-go/informers/core/v1"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"

	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func TestDeleterControllerFilter(t *testing.T) {
	defineSharedKubecertagentFilterSpecs(
		t,
		"DeleterControllerFilter",
		func(
			agentPodTemplate *corev1.Pod,
			kubeSystemPodInformer corev1informers.PodInformer,
			agentPodInformer corev1informers.PodInformer,
			observableWithInformerOption *testutil.ObservableWithInformerOption,
		) {
			_ = NewDeleterController(
				&Info{
					Template: agentPodTemplate,
				},
				nil, // k8sClient, shouldn't matter
				kubeSystemPodInformer,
				agentPodInformer,
				observableWithInformerOption.WithInformer,
			)
		},
	)
}

func TestDeleterControllerSync(t *testing.T) {
	spec.Run(t, "DeleterControllerSync", func(t *testing.T, when spec.G, it spec.S) {
		const kubeSystemNamespace = "kube-system"

		var r *require.Assertions

		var subject controllerlib.Controller
		var kubeAPIClient *kubernetesfake.Clientset
		var kubeSystemInformerClient *kubernetesfake.Clientset
		var kubeSystemInformers kubeinformers.SharedInformerFactory
		var agentInformerClient *kubernetesfake.Clientset
		var agentInformers kubeinformers.SharedInformerFactory
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var syncContext *controllerlib.Context

		agentPodTemplate := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "some-agent-name-",
				Labels: map[string]string{
					"some-label-key": "some-label-value",
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "some-agent-image",
					},
				},
			},
		}

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

		podsGVR := schema.GroupVersionResource{
			Group:    corev1.SchemeGroupVersion.Group,
			Version:  corev1.SchemeGroupVersion.Version,
			Resource: "pods",
		}

		// fnv 32a hash of controller-manager uid
		controllerManagerPodHash := "fbb0addd"
		agentPod := agentPodTemplate.DeepCopy()
		agentPod.Namespace = kubeSystemNamespace
		agentPod.Name += controllerManagerPodHash
		agentPod.Annotations = map[string]string{
			"kube-cert-agent.pinniped.dev/controller-manager-name": controllerManagerPod.Name,
			"kube-cert-agent.pinniped.dev/controller-manager-uid":  string(controllerManagerPod.UID),
		}
		agentPod.Spec.Containers[0].VolumeMounts = controllerManagerPod.Spec.Containers[0].VolumeMounts
		agentPod.Spec.RestartPolicy = corev1.RestartPolicyNever
		agentPod.Spec.AutomountServiceAccountToken = boolPtr(false)
		agentPod.Spec.NodeName = controllerManagerPod.Spec.NodeName
		agentPod.Spec.NodeSelector = controllerManagerPod.Spec.NodeSelector
		agentPod.Spec.Tolerations = controllerManagerPod.Spec.Tolerations

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewDeleterController(
				&Info{
					Template: agentPodTemplate,
				},
				kubeAPIClient,
				kubeSystemInformers.Core().V1().Pods(),
				agentInformers.Core().V1().Pods(),
				controllerlib.WithInformer,
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: timeoutContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Namespace: kubeSystemNamespace,
					Name:      "should-not-matter",
				},
			}

			// Must start informers before calling TestRunSynchronously()
			kubeSystemInformers.Start(timeoutContext.Done())
			agentInformers.Start(timeoutContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		it.Before(func() {
			r = require.New(t)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			kubeAPIClient = kubernetesfake.NewSimpleClientset()

			kubeSystemInformerClient = kubernetesfake.NewSimpleClientset()
			kubeSystemInformers = kubeinformers.NewSharedInformerFactory(kubeSystemInformerClient, 0)

			agentInformerClient = kubernetesfake.NewSimpleClientset()
			agentInformers = kubeinformers.NewSharedInformerFactory(agentInformerClient, 0)

			// Add an pod into the test that doesn't matter to make sure we don't accidentally
			// trigger any logic on this thing.
			ignorablePod := corev1.Pod{}
			ignorablePod.Name = "some-ignorable-pod"
			r.NoError(kubeSystemInformerClient.Tracker().Add(&ignorablePod))
			r.NoError(agentInformerClient.Tracker().Add(&ignorablePod))
			r.NoError(kubeAPIClient.Tracker().Add(&ignorablePod))
		})

		it.After(func() {
			timeoutContextCancel()
		})

		when("there is an agent pod", func() {
			it.Before(func() {
				r.NoError(agentInformerClient.Tracker().Add(agentPod))
				r.NoError(kubeAPIClient.Tracker().Add(agentPod))
			})

			when("there is a matching controller manager pod", func() {
				it.Before(func() {
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("does nothing", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("there is a non-matching controller manager pod via uid", func() {
				it.Before(func() {
					controllerManagerPod.UID = "some-other-controller-manager-uid"
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("deletes the agent pod", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{
							coretesting.NewDeleteAction(
								podsGVR,
								kubeSystemNamespace,
								agentPod.Name,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("there is a non-matching controller manager pod via name", func() {
				it.Before(func() {
					controllerManagerPod.Name = "some-other-controller-manager-name"
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("deletes the agent pod", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{
							coretesting.NewDeleteAction(
								podsGVR,
								kubeSystemNamespace,
								agentPod.Name,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("the agent pod is out of sync with the controller manager via volume mounts", func() {
				it.Before(func() {
					controllerManagerPod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{
						{
							Name: "some-other-volume-mount",
						},
					}
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("deletes the agent pod", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{
							coretesting.NewDeleteAction(
								podsGVR,
								kubeSystemNamespace,
								agentPod.Name,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("the agent pod is out of sync with the controller manager via volumes", func() {
				it.Before(func() {
					controllerManagerPod.Spec.Volumes = []corev1.Volume{
						{
							Name: "some-other-volume",
						},
					}
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("deletes the agent pod", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{
							coretesting.NewDeleteAction(
								podsGVR,
								kubeSystemNamespace,
								agentPod.Name,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("the agent pod is out of sync with the controller manager via node selector", func() {
				it.Before(func() {
					controllerManagerPod.Spec.NodeSelector = map[string]string{
						"some-other-node-selector-key": "some-other-node-selector-value",
					}
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("deletes the agent pod", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{
							coretesting.NewDeleteAction(
								podsGVR,
								kubeSystemNamespace,
								agentPod.Name,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("the agent pod is out of sync with the controller manager via node name", func() {
				it.Before(func() {
					controllerManagerPod.Spec.NodeName = "some-other-node-name"
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("deletes the agent pod", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{
							coretesting.NewDeleteAction(
								podsGVR,
								kubeSystemNamespace,
								agentPod.Name,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("the agent pod is out of sync with the controller manager via tolerations", func() {
				it.Before(func() {
					controllerManagerPod.Spec.Tolerations = []corev1.Toleration{
						{
							Key: "some-other-toleration-key",
						},
					}
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("deletes the agent pod", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{
							coretesting.NewDeleteAction(
								podsGVR,
								kubeSystemNamespace,
								agentPod.Name,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("the agent pod is out of sync via restart policy", func() {
				it.Before(func() {
					updatedAgentPod := agentPod.DeepCopy()
					updatedAgentPod.Spec.RestartPolicy = corev1.RestartPolicyAlways
					r.NoError(agentInformerClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
					r.NoError(kubeAPIClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
				})

				it("deletes the agent pod", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{
							coretesting.NewDeleteAction(
								podsGVR,
								kubeSystemNamespace,
								agentPod.Name,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("the agent pod is out of sync via automount service account tokem", func() {
				it.Before(func() {
					agentPod.Spec.AutomountServiceAccountToken = boolPtr(true)
					r.NoError(agentInformerClient.Tracker().Update(podsGVR, agentPod, agentPod.Namespace))
					r.NoError(kubeAPIClient.Tracker().Update(podsGVR, agentPod, agentPod.Namespace))
				})

				it("deletes the agent pod", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{
							coretesting.NewDeleteAction(
								podsGVR,
								kubeSystemNamespace,
								agentPod.Name,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("there is no matching controller manager pod", func() {
				it("deletes the agent pod", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{
							coretesting.NewDeleteAction(
								podsGVR,
								kubeSystemNamespace,
								agentPod.Name,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})
		})

		when("there is no agent pod", func() {
			it("does nothing", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)

				r.NoError(err)
				r.Equal(
					[]coretesting.Action{},
					kubeAPIClient.Actions(),
				)
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
