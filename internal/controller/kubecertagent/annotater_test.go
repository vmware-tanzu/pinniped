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
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeinformers "k8s.io/client-go/informers"
	corev1informers "k8s.io/client-go/informers/core/v1"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"

	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func TestAnnotaterControllerFilter(t *testing.T) {
	defineSharedKubecertagentFilterSpecs(
		t,
		"AnnotaterControllerFilter",
		func(
			agentPodConfig *AgentPodConfig,
			_ *CredentialIssuerConfigLocationConfig,
			kubeSystemPodInformer corev1informers.PodInformer,
			agentPodInformer corev1informers.PodInformer,
			observableWithInformerOption *testutil.ObservableWithInformerOption,
		) {
			_ = NewAnnotaterController(
				agentPodConfig,
				nil, // k8sClient, shouldn't matter
				kubeSystemPodInformer,
				agentPodInformer,
				observableWithInformerOption.WithInformer,
			)
		},
	)
}

func TestAnnotaterControllerSync(t *testing.T) {
	spec.Run(t, "AnnotaterControllerSync", func(t *testing.T, when spec.G, it spec.S) {
		const kubeSystemNamespace = "kube-system"
		const agentPodNamespace = "agent-pod-namespace"
		const defaultKubeControllerManagerClusterSigningCertFileFlagValue = "/etc/kubernetes/ca/ca.pem"
		const defaultKubeControllerManagerClusterSigningKeyFileFlagValue = "/etc/kubernetes/ca/ca.key"

		const (
			certPath           = "some-cert-path"
			certPathAnnotation = "kube-cert-agent.pinniped.dev/cert-path"

			keyPath           = "some-key-path"
			keyPathAnnotation = "kube-cert-agent.pinniped.dev/key-path"
		)

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
		var controllerManagerPod, agentPod *corev1.Pod
		var podsGVR schema.GroupVersionResource

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewAnnotaterController(
				&AgentPodConfig{
					Namespace:      agentPodNamespace,
					ContainerImage: "some-agent-image",
					PodNamePrefix:  "some-agent-name-",
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

			kubeAPIClient = kubernetesfake.NewSimpleClientset()

			kubeSystemInformerClient = kubernetesfake.NewSimpleClientset()
			kubeSystemInformers = kubeinformers.NewSharedInformerFactory(kubeSystemInformerClient, 0)

			agentInformerClient = kubernetesfake.NewSimpleClientset()
			agentInformers = kubeinformers.NewSharedInformerFactory(agentInformerClient, 0)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			controllerManagerPod, agentPod = exampleControllerManagerAndAgentPods(
				kubeSystemNamespace, agentPodNamespace, certPath, keyPath,
			)

			podsGVR = schema.GroupVersionResource{
				Group:    corev1.SchemeGroupVersion.Group,
				Version:  corev1.SchemeGroupVersion.Version,
				Resource: "pods",
			}

			// Add a pod into the test that doesn't matter to make sure we don't accidentally trigger any
			// logic on this thing.
			ignorablePod := corev1.Pod{}
			ignorablePod.Name = "some-ignorable-pod"
			r.NoError(kubeSystemInformerClient.Tracker().Add(&ignorablePod))
			r.NoError(agentInformerClient.Tracker().Add(&ignorablePod))
			r.NoError(kubeAPIClient.Tracker().Add(&ignorablePod))
		})

		it.After(func() {
			timeoutContextCancel()
		})

		when("there is an agent pod without annotations set", func() {
			it.Before(func() {
				r.NoError(agentInformerClient.Tracker().Add(agentPod))
				r.NoError(kubeAPIClient.Tracker().Add(agentPod))
			})

			when("there is a matching controller manager pod", func() {
				it.Before(func() {
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("updates the annotations according to the controller manager pod", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					updatedAgentPod := agentPod.DeepCopy()
					updatedAgentPod.Annotations[certPathAnnotation] = certPath
					updatedAgentPod.Annotations[keyPathAnnotation] = keyPath

					r.Equal(
						[]coretesting.Action{
							coretesting.NewUpdateAction(
								podsGVR,
								agentPodNamespace,
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
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("updates the annotations according to the controller manager pod", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					updatedAgentPod := agentPod.DeepCopy()
					updatedAgentPod.Annotations[certPathAnnotation] = certPath
					updatedAgentPod.Annotations[keyPathAnnotation] = keyPath

					r.Equal(
						[]coretesting.Action{
							coretesting.NewUpdateAction(
								podsGVR,
								agentPodNamespace,
								updatedAgentPod,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("there is a controller manager pod with no CLI flags", func() {
				it.Before(func() {
					controllerManagerPod.Spec.Containers[0].Command = []string{
						"kube-controller-manager",
					}
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("updates the annotations with the default values", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					updatedAgentPod := agentPod.DeepCopy()
					updatedAgentPod.Annotations[certPathAnnotation] = defaultKubeControllerManagerClusterSigningCertFileFlagValue
					updatedAgentPod.Annotations[keyPathAnnotation] = defaultKubeControllerManagerClusterSigningKeyFileFlagValue

					r.Equal(
						[]coretesting.Action{
							coretesting.NewUpdateAction(
								podsGVR,
								agentPodNamespace,
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
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("updates the annotations with the default values", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					updatedAgentPod := agentPod.DeepCopy()
					updatedAgentPod.Annotations[certPathAnnotation] = defaultKubeControllerManagerClusterSigningCertFileFlagValue
					updatedAgentPod.Annotations[keyPathAnnotation] = defaultKubeControllerManagerClusterSigningKeyFileFlagValue

					r.Equal(
						[]coretesting.Action{
							coretesting.NewUpdateAction(
								podsGVR,
								agentPodNamespace,
								updatedAgentPod,
							),
						},
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
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("updates the key annotation with the default cert flag value", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					updatedAgentPod := agentPod.DeepCopy()
					updatedAgentPod.Annotations[certPathAnnotation] = defaultKubeControllerManagerClusterSigningCertFileFlagValue
					updatedAgentPod.Annotations[keyPathAnnotation] = keyPath

					r.Equal(
						[]coretesting.Action{
							coretesting.NewUpdateAction(
								podsGVR,
								agentPodNamespace,
								updatedAgentPod,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("there is a controller manager pod with unparsable key CLI flag", func() {
				it.Before(func() {
					controllerManagerPod.Spec.Containers[0].Command = []string{
						"kube-controller-manager",
						"--cluster-signing-cert-file", certPath,
						"--cluster-signing-key-file-blah", keyPath,
					}
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
					r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
				})

				it("updates the cert annotation with the default key flag value", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					updatedAgentPod := agentPod.DeepCopy()
					updatedAgentPod.Annotations[certPathAnnotation] = certPath
					updatedAgentPod.Annotations[keyPathAnnotation] = defaultKubeControllerManagerClusterSigningKeyFileFlagValue

					r.Equal(
						[]coretesting.Action{
							coretesting.NewUpdateAction(
								podsGVR,
								agentPodNamespace,
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
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
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
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
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
				r.NoError(agentInformerClient.Tracker().Add(agentPod))
				r.NoError(kubeAPIClient.Tracker().Add(agentPod))
			})

			when("there is a matching controller manager pod", func() {
				it.Before(func() {
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
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
				agentPod.Annotations[certPathAnnotation] = "wrong"
				agentPod.Annotations[keyPathAnnotation] = keyPath
				r.NoError(agentInformerClient.Tracker().Add(agentPod))
				r.NoError(kubeAPIClient.Tracker().Add(agentPod))
			})

			when("there is a matching controller manager pod", func() {
				it.Before(func() {
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
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
								agentPodNamespace,
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
				agentPod.Annotations[certPathAnnotation] = certPath
				agentPod.Annotations[keyPathAnnotation] = "key"
				r.NoError(agentInformerClient.Tracker().Add(agentPod))
				r.NoError(kubeAPIClient.Tracker().Add(agentPod))
			})

			when("there is a matching controller manager pod", func() {
				it.Before(func() {
					r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
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
								agentPodNamespace,
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
