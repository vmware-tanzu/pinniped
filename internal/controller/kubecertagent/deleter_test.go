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

func TestDeleterControllerFilter(t *testing.T) {
	defineSharedKubecertagentFilterSpecs(
		t,
		"DeleterControllerFilter",
		func(
			agentPodConfig *AgentPodConfig,
			_ *CredentialIssuerConfigLocationConfig,
			kubeSystemPodInformer corev1informers.PodInformer,
			agentPodInformer corev1informers.PodInformer,
			observableWithInformerOption *testutil.ObservableWithInformerOption,
		) {
			_ = NewDeleterController(
				agentPodConfig,
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
		const agentPodNamespace = "agent-pod-namespace"

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
			subject = NewDeleterController(
				&AgentPodConfig{
					Namespace:      agentPodNamespace,
					ContainerImage: "some-agent-image",
					PodNamePrefix:  "some-agent-name-",
					AdditionalLabels: map[string]string{
						"myLabelKey1": "myLabelValue1",
						"myLabelKey2": "myLabelValue2",
					},
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

		var requireAgentPodWasDeleted = func() {
			r.Equal(
				[]coretesting.Action{coretesting.NewDeleteAction(podsGVR, agentPodNamespace, agentPod.Name)},
				kubeAPIClient.Actions(),
			)
		}

		it.Before(func() {
			r = require.New(t)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			kubeAPIClient = kubernetesfake.NewSimpleClientset()

			kubeSystemInformerClient = kubernetesfake.NewSimpleClientset()
			kubeSystemInformers = kubeinformers.NewSharedInformerFactory(kubeSystemInformerClient, 0)

			agentInformerClient = kubernetesfake.NewSimpleClientset()
			agentInformers = kubeinformers.NewSharedInformerFactory(agentInformerClient, 0)

			controllerManagerPod, agentPod = exampleControllerManagerAndAgentPods(
				kubeSystemNamespace, agentPodNamespace, "ignored for this test", "ignored for this test",
			)

			podsGVR = schema.GroupVersionResource{
				Group:    corev1.SchemeGroupVersion.Group,
				Version:  corev1.SchemeGroupVersion.Version,
				Resource: "pods",
			}

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
					r.Empty(kubeAPIClient.Actions())
				})

				when("the agent pod is out of sync with the controller manager via volume mounts", func() {
					it.Before(func() {
						controllerManagerPod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "some-other-volume-mount"}}
						r.NoError(kubeSystemInformerClient.Tracker().Update(podsGVR, controllerManagerPod, controllerManagerPod.Namespace))
						r.NoError(kubeAPIClient.Tracker().Update(podsGVR, controllerManagerPod, controllerManagerPod.Namespace))
					})

					it("deletes the agent pod", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)

						r.NoError(err)
						requireAgentPodWasDeleted()
					})
				})

				when("the agent pod is out of sync with the controller manager via volumes", func() {
					it.Before(func() {
						controllerManagerPod.Spec.Volumes = []corev1.Volume{{Name: "some-other-volume"}}
						r.NoError(kubeSystemInformerClient.Tracker().Update(podsGVR, controllerManagerPod, controllerManagerPod.Namespace))
						r.NoError(kubeAPIClient.Tracker().Update(podsGVR, controllerManagerPod, controllerManagerPod.Namespace))
					})

					it("deletes the agent pod", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)

						r.NoError(err)
						requireAgentPodWasDeleted()
					})
				})

				when("the agent pod is out of sync with the controller manager via node selector", func() {
					it.Before(func() {
						controllerManagerPod.Spec.NodeSelector = map[string]string{
							"some-other-node-selector-key": "some-other-node-selector-value",
						}
						r.NoError(kubeSystemInformerClient.Tracker().Update(podsGVR, controllerManagerPod, controllerManagerPod.Namespace))
						r.NoError(kubeAPIClient.Tracker().Update(podsGVR, controllerManagerPod, controllerManagerPod.Namespace))
					})

					it("deletes the agent pod", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)

						r.NoError(err)
						requireAgentPodWasDeleted()
					})
				})

				when("the agent pod is out of sync with the controller manager via node name", func() {
					it.Before(func() {
						controllerManagerPod.Spec.NodeName = "some-other-node-name"
						r.NoError(kubeSystemInformerClient.Tracker().Update(podsGVR, controllerManagerPod, controllerManagerPod.Namespace))
						r.NoError(kubeAPIClient.Tracker().Update(podsGVR, controllerManagerPod, controllerManagerPod.Namespace))
					})

					it("deletes the agent pod", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)

						r.NoError(err)
						requireAgentPodWasDeleted()
					})
				})

				when("the agent pod is out of sync with the controller manager via tolerations", func() {
					it.Before(func() {
						controllerManagerPod.Spec.Tolerations = []corev1.Toleration{{Key: "some-other-toleration-key"}}
						r.NoError(kubeSystemInformerClient.Tracker().Update(podsGVR, controllerManagerPod, controllerManagerPod.Namespace))
						r.NoError(kubeAPIClient.Tracker().Update(podsGVR, controllerManagerPod, controllerManagerPod.Namespace))
					})

					it("deletes the agent pod", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)

						r.NoError(err)
						requireAgentPodWasDeleted()
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
						requireAgentPodWasDeleted()
					})
				})

				when("the agent pod is out of sync via automount service account token", func() {
					it.Before(func() {
						updatedAgentPod := agentPod.DeepCopy()
						updatedAgentPod.Spec.AutomountServiceAccountToken = boolPtr(true)
						r.NoError(agentInformerClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
						r.NoError(kubeAPIClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
					})

					it("deletes the agent pod", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)

						r.NoError(err)
						requireAgentPodWasDeleted()
					})
				})

				when("the agent pod is out of sync with the template via name", func() {
					it.Before(func() {
						updatedAgentPod := agentPod.DeepCopy()
						updatedAgentPod.Spec.Containers[0].Name = "some-new-name"
						r.NoError(agentInformerClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
						r.NoError(kubeAPIClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
					})

					it("deletes the agent pod", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)

						r.NoError(err)
						requireAgentPodWasDeleted()
					})
				})

				when("the agent pod is out of sync with the template via image", func() {
					it.Before(func() {
						updatedAgentPod := agentPod.DeepCopy()
						updatedAgentPod.Spec.Containers[0].Image = "new-image"
						r.NoError(agentInformerClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
						r.NoError(kubeAPIClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
					})

					it("deletes the agent pod", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)

						r.NoError(err)
						requireAgentPodWasDeleted()
					})
				})

				when("the agent pod is out of sync with the template via labels", func() {
					when("an additional label's value was changed", func() {
						it.Before(func() {
							updatedAgentPod := agentPod.DeepCopy()
							updatedAgentPod.ObjectMeta.Labels = map[string]string{
								"kube-cert-agent.pinniped.dev": "true",
								// the value of a label is wrong so the pod should be deleted so it can get recreated with the new labels
								"myLabelKey1": "myLabelValue1-outdated-value",
								"myLabelKey2": "myLabelValue2-outdated-value",
							}
							r.NoError(agentInformerClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
							r.NoError(kubeAPIClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
						})

						it("deletes the agent pod", func() {
							startInformersAndController()
							err := controllerlib.TestSync(t, subject, *syncContext)

							r.NoError(err)
							requireAgentPodWasDeleted()
						})
					})

					when("an additional custom label was added since the agent pod was created", func() {
						it.Before(func() {
							updatedAgentPod := agentPod.DeepCopy()
							updatedAgentPod.ObjectMeta.Labels = map[string]string{
								"kube-cert-agent.pinniped.dev": "true",
								"myLabelKey1":                  "myLabelValue1",
								// "myLabelKey2" is missing so the pod should be deleted so it can get recreated with the new labels
							}
							r.NoError(agentInformerClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
							r.NoError(kubeAPIClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
						})

						it("deletes the agent pod", func() {
							startInformersAndController()
							err := controllerlib.TestSync(t, subject, *syncContext)

							r.NoError(err)
							requireAgentPodWasDeleted()
						})
					})

					when("the agent pod has extra labels that seem unrelated to the additional labels", func() {
						it.Before(func() {
							updatedAgentPod := agentPod.DeepCopy()
							updatedAgentPod.ObjectMeta.Labels = map[string]string{
								"kube-cert-agent.pinniped.dev": "true",
								"myLabelKey1":                  "myLabelValue1",
								"myLabelKey2":                  "myLabelValue2",
								"extra-label":                  "not-related-to-the-sepcified-additional-labels",
							}
							r.NoError(agentInformerClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
							r.NoError(kubeAPIClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
						})

						it("does not delete the agent pod because someone else might have put those labels on it", func() {
							startInformersAndController()
							err := controllerlib.TestSync(t, subject, *syncContext)

							r.NoError(err)
							r.Empty(kubeAPIClient.Actions())
						})
					})
				})

				when("the agent pod is out of sync with the template via command", func() {
					it.Before(func() {
						updatedAgentPod := agentPod.DeepCopy()
						updatedAgentPod.Spec.Containers[0].Command = []string{"some", "new", "command"}
						r.NoError(agentInformerClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
						r.NoError(kubeAPIClient.Tracker().Update(podsGVR, updatedAgentPod, updatedAgentPod.Namespace))
					})

					it("deletes the agent pod", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)

						r.NoError(err)
						requireAgentPodWasDeleted()
					})
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
					requireAgentPodWasDeleted()
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
					requireAgentPodWasDeleted()
				})
			})

			when("there is no matching controller manager pod", func() {
				it("deletes the agent pod", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					requireAgentPodWasDeleted()
				})
			})
		})

		when("there is no agent pod", func() {
			it("does nothing", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)

				r.NoError(err)
				r.Empty(kubeAPIClient.Actions())
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
