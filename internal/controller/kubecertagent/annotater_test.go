// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/clock"
	kubeinformers "k8s.io/client-go/informers"
	corev1informers "k8s.io/client-go/informers/core/v1"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func TestAnnotaterControllerFilter(t *testing.T) {
	defineSharedKubecertagentFilterSpecs(
		t,
		"AnnotaterControllerFilter",
		func(
			agentPodConfig *AgentPodConfig,
			_ *CredentialIssuerLocationConfig,
			kubeSystemPodInformer corev1informers.PodInformer,
			agentPodInformer corev1informers.PodInformer,
			observableWithInformerOption *testutil.ObservableWithInformerOption,
		) {
			_ = NewAnnotaterController(
				agentPodConfig,
				nil, // credentialIssuerLabels, shouldn't matter
				nil, // credentialIssuerLocationConfig, shouldn't matter
				nil, // clock, shouldn't matter
				nil, // k8sClient, shouldn't matter
				nil, // pinnipedClient, shouldn't matter
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
		const credentialIssuerResourceName = "ci-resource-name"

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
		var pinnipedAPIClient *pinnipedfake.Clientset
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var syncContext *controllerlib.Context
		var controllerManagerPod, agentPod *corev1.Pod
		var podsGVR schema.GroupVersionResource
		var credentialIssuerGVR schema.GroupVersionResource
		var frozenNow time.Time
		var credentialIssuerLabels map[string]string

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewAnnotaterController(
				&AgentPodConfig{
					Namespace:      agentPodNamespace,
					ContainerImage: "some-agent-image",
					PodNamePrefix:  "some-agent-name-",
					AdditionalLabels: map[string]string{
						"myLabelKey1": "myLabelValue1",
						"myLabelKey2": "myLabelValue2",
					},
				},
				&CredentialIssuerLocationConfig{
					Name: credentialIssuerResourceName,
				},
				credentialIssuerLabels,
				clock.NewFakeClock(frozenNow),
				kubeAPIClient,
				pinnipedAPIClient,
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

			pinnipedAPIClient = pinnipedfake.NewSimpleClientset()

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			controllerManagerPod, agentPod = exampleControllerManagerAndAgentPods(
				kubeSystemNamespace, agentPodNamespace, certPath, keyPath,
			)

			podsGVR = schema.GroupVersionResource{
				Group:    corev1.SchemeGroupVersion.Group,
				Version:  corev1.SchemeGroupVersion.Version,
				Resource: "pods",
			}

			credentialIssuerGVR = schema.GroupVersionResource{
				Group:    configv1alpha1.GroupName,
				Version:  configv1alpha1.SchemeGroupVersion.Version,
				Resource: "credentialissuers",
			}

			frozenNow = time.Date(2020, time.September, 23, 7, 42, 0, 0, time.Local)

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
							coretesting.NewGetAction(
								podsGVR,
								agentPodNamespace,
								updatedAgentPod.Name,
							),
							coretesting.NewUpdateAction(
								podsGVR,
								agentPodNamespace,
								updatedAgentPod,
							),
						},
						kubeAPIClient.Actions(),
					)
				})

				when("updating the agent pod fails", func() {
					it.Before(func() {
						kubeAPIClient.PrependReactor(
							"update",
							"pods",
							func(_ coretesting.Action) (bool, runtime.Object, error) {
								return true, nil, errors.New("some update error")
							},
						)
					})

					it("returns the error", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)
						r.EqualError(err, "cannot update agent pod: some update error")
					})

					when("there is already a CredentialIssuer", func() {
						var initialCredentialIssuer *configv1alpha1.CredentialIssuer

						it.Before(func() {
							initialCredentialIssuer = &configv1alpha1.CredentialIssuer{
								TypeMeta: metav1.TypeMeta{},
								ObjectMeta: metav1.ObjectMeta{
									Name: credentialIssuerResourceName,
								},
								Status: configv1alpha1.CredentialIssuerStatus{
									Strategies: []configv1alpha1.CredentialIssuerStrategy{},
								},
							}
							r.NoError(pinnipedAPIClient.Tracker().Add(initialCredentialIssuer))
						})

						it("updates the CredentialIssuer status with the error", func() {
							startInformersAndController()
							err := controllerlib.TestSync(t, subject, *syncContext)

							expectedCredentialIssuer := initialCredentialIssuer.DeepCopy()
							expectedCredentialIssuer.Status.Strategies = []configv1alpha1.CredentialIssuerStrategy{
								{
									Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
									Status:         configv1alpha1.ErrorStrategyStatus,
									Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
									Message:        "cannot update agent pod: some update error",
									LastUpdateTime: metav1.NewTime(frozenNow),
								},
							}
							expectedGetAction := coretesting.NewRootGetAction(
								credentialIssuerGVR,
								credentialIssuerResourceName,
							)
							expectedUpdateAction := coretesting.NewRootUpdateSubresourceAction(
								credentialIssuerGVR,
								"status",
								expectedCredentialIssuer,
							)

							r.EqualError(err, "cannot update agent pod: some update error")
							r.Equal(
								[]coretesting.Action{
									expectedGetAction,
									expectedUpdateAction,
								},
								pinnipedAPIClient.Actions(),
							)
						})

						when("updating the CredentialIssuer fails", func() {
							it.Before(func() {
								pinnipedAPIClient.PrependReactor(
									"update",
									"credentialissuers",
									func(_ coretesting.Action) (bool, runtime.Object, error) {
										return true, nil, errors.New("some update error")
									},
								)
							})

							it("returns the original pod update error so the controller gets scheduled again", func() {
								startInformersAndController()
								err := controllerlib.TestSync(t, subject, *syncContext)
								r.EqualError(err, "cannot update agent pod: some update error")
							})
						})
					})

					when("there is not already a CredentialIssuer", func() {
						it.Before(func() {
							credentialIssuerLabels = map[string]string{"foo": "bar"}
						})

						it("creates the CredentialIssuer status with the error", func() {
							startInformersAndController()
							err := controllerlib.TestSync(t, subject, *syncContext)

							expectedCreateCredentialIssuer := &configv1alpha1.CredentialIssuer{
								TypeMeta: metav1.TypeMeta{},
								ObjectMeta: metav1.ObjectMeta{
									Name:   credentialIssuerResourceName,
									Labels: map[string]string{"foo": "bar"},
								},
							}

							expectedCredentialIssuer := &configv1alpha1.CredentialIssuer{
								TypeMeta: metav1.TypeMeta{},
								ObjectMeta: metav1.ObjectMeta{
									Name:   credentialIssuerResourceName,
									Labels: map[string]string{"foo": "bar"},
								},
								Status: configv1alpha1.CredentialIssuerStatus{
									Strategies: []configv1alpha1.CredentialIssuerStrategy{
										{
											Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
											Status:         configv1alpha1.ErrorStrategyStatus,
											Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
											Message:        "cannot update agent pod: some update error",
											LastUpdateTime: metav1.NewTime(frozenNow),
										},
									},
								},
							}
							expectedGetAction := coretesting.NewRootGetAction(
								credentialIssuerGVR,
								credentialIssuerResourceName,
							)
							expectedCreateAction := coretesting.NewRootCreateAction(
								credentialIssuerGVR,
								expectedCreateCredentialIssuer,
							)
							expectedUpdateAction := coretesting.NewRootUpdateSubresourceAction(
								credentialIssuerGVR,
								"status",
								expectedCredentialIssuer,
							)

							r.EqualError(err, "cannot update agent pod: some update error")
							r.Equal(
								[]coretesting.Action{
									expectedGetAction,
									expectedCreateAction,
									expectedUpdateAction,
								},
								pinnipedAPIClient.Actions(),
							)
						})
					})
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
							coretesting.NewGetAction(
								podsGVR,
								agentPodNamespace,
								updatedAgentPod.Name,
							),
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
							coretesting.NewGetAction(
								podsGVR,
								agentPodNamespace,
								updatedAgentPod.Name,
							),
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
							coretesting.NewGetAction(
								podsGVR,
								agentPodNamespace,
								updatedAgentPod.Name,
							),
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
							coretesting.NewGetAction(
								podsGVR,
								agentPodNamespace,
								updatedAgentPod.Name,
							),
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
							coretesting.NewGetAction(
								podsGVR,
								agentPodNamespace,
								updatedAgentPod.Name,
							),
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

		when("there is an agent pod without annotations set which does not have the configured additional labels", func() {
			it.Before(func() {
				delete(agentPod.ObjectMeta.Labels, "myLabelKey1")
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
							coretesting.NewGetAction(
								podsGVR,
								agentPodNamespace,
								updatedAgentPod.Name,
							),
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
							coretesting.NewGetAction(
								podsGVR,
								agentPodNamespace,
								updatedAgentPod.Name,
							),
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
							coretesting.NewGetAction(
								podsGVR,
								agentPodNamespace,
								updatedAgentPod.Name,
							),
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
