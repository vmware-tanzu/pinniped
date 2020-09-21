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

func TestAnnotaterControllerFilter(t *testing.T) {
	runFilterTest(
		t,
		"AnnotaterControllerFilter",
		func(
			agentPodTemplate *corev1.Pod,
			podsInformer corev1informers.PodInformer,
			observableWithInformerOption *testutil.ObservableWithInformerOption,
		) {
			_ = NewAnnotaterController(
				&Info{
					Template: agentPodTemplate,
				},
				nil, // k8sClient, shouldn't matter
				podsInformer,
				observableWithInformerOption.WithInformer,
			)
		},
	)
}

func TestAnnotaterControllerSync(t *testing.T) {
	spec.Run(t, "AnnotaterControllerSync", func(t *testing.T, when spec.G, it spec.S) {
		const kubeSystemNamespace = "kube-system"

		const (
			certPath           = "some-cert-path"
			certPathAnnotation = "some-cert-path-annotation"

			keyPath           = "some-key-path"
			keyPathAnnotation = "some-key-path-annotation"
		)

		var r *require.Assertions

		var subject controllerlib.Controller
		var kubeAPIClient *kubernetesfake.Clientset
		var kubeInformerClient *kubernetesfake.Clientset
		var kubeInformers kubeinformers.SharedInformerFactory
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

		// fnv 32a hash of controller-manager uid
		controllerManagerPodHash := "fbb0addd"
		agentPod := agentPodTemplate.DeepCopy()
		agentPod.Namespace = kubeSystemNamespace
		agentPod.Name += controllerManagerPodHash
		agentPod.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion:         "v1",
				Kind:               "Pod",
				Name:               controllerManagerPod.Name,
				UID:                controllerManagerPod.UID,
				Controller:         boolPtr(true),
				BlockOwnerDeletion: boolPtr(true),
			},
		}
		agentPod.Spec.Containers[0].VolumeMounts = controllerManagerPod.Spec.Containers[0].VolumeMounts
		agentPod.Spec.RestartPolicy = corev1.RestartPolicyNever
		agentPod.Spec.AutomountServiceAccountToken = boolPtr(false)
		agentPod.Spec.NodeName = controllerManagerPod.Spec.NodeName
		agentPod.Spec.NodeSelector = controllerManagerPod.Spec.NodeSelector
		agentPod.Spec.Tolerations = controllerManagerPod.Spec.Tolerations

		podsGVR := schema.GroupVersionResource{
			Group:    corev1.SchemeGroupVersion.Group,
			Version:  corev1.SchemeGroupVersion.Version,
			Resource: "pods",
		}

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewAnnotaterController(
				&Info{
					Template:           agentPodTemplate,
					CertPathAnnotation: certPathAnnotation,
					KeyPathAnnotation:  keyPathAnnotation,
				},
				kubeAPIClient,
				kubeInformers.Core().V1().Pods(),
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
			kubeInformers.Start(timeoutContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		it.Before(func() {
			r = require.New(t)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			kubeInformerClient = kubernetesfake.NewSimpleClientset()
			kubeInformers = kubeinformers.NewSharedInformerFactory(kubeInformerClient, 0)
			kubeAPIClient = kubernetesfake.NewSimpleClientset()

			// Add a pod into the test that doesn't matter to make sure we don't accidentally trigger any
			// logic on this thing.
			ignorablePod := corev1.Pod{}
			ignorablePod.Name = "some-ignorable-pod"
			r.NoError(kubeInformerClient.Tracker().Add(&ignorablePod))
			r.NoError(kubeAPIClient.Tracker().Add(&ignorablePod))
		})

		it.After(func() {
			timeoutContextCancel()
		})

		when("there is an agent pod without annotations set", func() {
			it.Before(func() {
				r.NoError(kubeInformerClient.Tracker().Add(agentPod))
				r.NoError(kubeAPIClient.Tracker().Add(agentPod))
			})

			when("there is a matching controller manager pod", func() {
				it.Before(func() {
					r.NoError(kubeInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("updates the annotations according to the controller manager pod", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					updatedAgentPod := agentPod.DeepCopy()
					updatedAgentPod.Annotations = make(map[string]string)
					updatedAgentPod.Annotations[certPathAnnotation] = certPath
					updatedAgentPod.Annotations[keyPathAnnotation] = keyPath

					r.Equal(
						[]coretesting.Action{
							coretesting.NewUpdateAction(
								podsGVR,
								kubeSystemNamespace,
								updatedAgentPod,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("there is a controller manager pod with CLI flag values separated by spaces", func() {
				it.Before(func() {
					controllerManagerPod.Spec.Containers[0].Command = []string{
						"kube-controller-manager",
						"--cluster-signing-cert-file", certPath,
						"--cluster-signing-key-file", keyPath,
					}
					r.NoError(kubeInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("updates the annotations according to the controller manager pod", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					updatedAgentPod := agentPod.DeepCopy()
					updatedAgentPod.Annotations = make(map[string]string)
					updatedAgentPod.Annotations[certPathAnnotation] = certPath
					updatedAgentPod.Annotations[keyPathAnnotation] = keyPath

					r.Equal(
						[]coretesting.Action{
							coretesting.NewUpdateAction(
								podsGVR,
								kubeSystemNamespace,
								updatedAgentPod,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("there is a controller manager pod with unparsable CLI flags", func() {
				it.Before(func() {
					controllerManagerPod.Spec.Containers[0].Command = []string{
						"kube-controller-manager",
						"--cluster-signing-cert-file-blah", certPath,
						"--cluster-signing-key-file-blah", keyPath,
					}
					r.NoError(kubeInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("does not update any annotations", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					r.Equal(
						[]coretesting.Action{},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("there is a controller manager pod with unparsable cert CLI flag", func() {
				it.Before(func() {
					controllerManagerPod.Spec.Containers[0].Command = []string{
						"kube-controller-manager",
						"--cluster-signing-cert-file-blah", certPath,
						"--cluster-signing-key-file", keyPath,
					}
					r.NoError(kubeInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("updates the key annotation", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					updatedAgentPod := agentPod.DeepCopy()
					updatedAgentPod.Annotations = make(map[string]string)
					updatedAgentPod.Annotations[keyPathAnnotation] = keyPath
					r.Equal(
						[]coretesting.Action{
							coretesting.NewUpdateAction(
								podsGVR,
								kubeSystemNamespace,
								updatedAgentPod,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("there is a controller manager pod with unparsable keey CLI flag", func() {
				it.Before(func() {
					controllerManagerPod.Spec.Containers[0].Command = []string{
						"kube-controller-manager",
						"--cluster-signing-cert-file", certPath,
						"--cluster-signing-key-file-blah", keyPath,
					}
					r.NoError(kubeInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("updates the cert annotation", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					updatedAgentPod := agentPod.DeepCopy()
					updatedAgentPod.Annotations = make(map[string]string)
					updatedAgentPod.Annotations[certPathAnnotation] = certPath
					r.Equal(
						[]coretesting.Action{
							coretesting.NewUpdateAction(
								podsGVR,
								kubeSystemNamespace,
								updatedAgentPod,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("there is a non-matching controller manager pod via uid", func() {
				it.Before(func() {
					controllerManagerPod.UID = "some-other-controller-manager-uid"
					r.NoError(kubeInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("does nothing; the deleter will delete this pod to trigger resync", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					r.Equal(
						[]coretesting.Action{},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("there is a non-matching controller manager pod via name", func() {
				it.Before(func() {
					controllerManagerPod.Name = "some-other-controller-manager-name"
					r.NoError(kubeInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("does nothing; the deleter will delete this pod to trigger resync", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					r.Equal(
						[]coretesting.Action{},
						kubeAPIClient.Actions(),
					)
				})
			})
		})

		when("there is an agent pod with correct annotations set", func() {
			it.Before(func() {
				agentPod.Annotations = make(map[string]string)
				agentPod.Annotations[certPathAnnotation] = certPath
				agentPod.Annotations[keyPathAnnotation] = keyPath
				r.NoError(kubeInformerClient.Tracker().Add(agentPod))
				r.NoError(kubeAPIClient.Tracker().Add(agentPod))
			})

			when("there is a matching controller manager pod", func() {
				it.Before(func() {
					r.NoError(kubeInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("does nothing since the pod is up to date", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					r.Equal(
						[]coretesting.Action{},
						kubeAPIClient.Actions(),
					)
				})
			})
		})

		when("there is an agent pod with the wrong cert annotation", func() {
			it.Before(func() {
				agentPod.Annotations = make(map[string]string)
				agentPod.Annotations[certPathAnnotation] = "wrong"
				agentPod.Annotations[keyPathAnnotation] = keyPath
				r.NoError(kubeInformerClient.Tracker().Add(agentPod))
				r.NoError(kubeAPIClient.Tracker().Add(agentPod))
			})

			when("there is a matching controller manager pod", func() {
				it.Before(func() {
					r.NoError(kubeInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("updates the agent with the correct cert annotation", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					updatedAgentPod := agentPod.DeepCopy()
					updatedAgentPod.Annotations[certPathAnnotation] = certPath
					r.Equal(
						[]coretesting.Action{
							coretesting.NewUpdateAction(
								podsGVR,
								kubeSystemNamespace,
								updatedAgentPod,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})
		})

		when("there is an agent pod with the wrong key annotation", func() {
			it.Before(func() {
				agentPod.Annotations = make(map[string]string)
				agentPod.Annotations[certPathAnnotation] = certPath
				agentPod.Annotations[keyPathAnnotation] = "key"
				r.NoError(kubeInformerClient.Tracker().Add(agentPod))
				r.NoError(kubeAPIClient.Tracker().Add(agentPod))
			})

			when("there is a matching controller manager pod", func() {
				it.Before(func() {
					r.NoError(kubeInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("updates the agent with the correct key annotation", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					updatedAgentPod := agentPod.DeepCopy()
					updatedAgentPod.Annotations[keyPathAnnotation] = keyPath
					r.Equal(
						[]coretesting.Action{
							coretesting.NewUpdateAction(
								podsGVR,
								kubeSystemNamespace,
								updatedAgentPod,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
