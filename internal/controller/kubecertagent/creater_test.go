// Copyright 2020 the Pinniped contributors. All Rights Reserved.
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

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/1.19/client/clientset/versioned/fake"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func TestCreaterControllerFilter(t *testing.T) {
	defineSharedKubecertagentFilterSpecs(
		t,
		"CreaterControllerFilter",
		func(
			agentPodConfig *AgentPodConfig,
			credentialIssuerConfigLocationConfig *CredentialIssuerConfigLocationConfig,
			kubeSystemPodInformer corev1informers.PodInformer,
			agentPodInformer corev1informers.PodInformer,
			observableWithInformerOption *testutil.ObservableWithInformerOption,
		) {
			_ = NewCreaterController(
				agentPodConfig,
				credentialIssuerConfigLocationConfig,
				map[string]string{},
				nil, // clock, shouldn't matter
				nil, // k8sClient, shouldn't matter
				nil, // pinnipedAPIClient, shouldn't matter
				kubeSystemPodInformer,
				agentPodInformer,
				observableWithInformerOption.WithInformer,
				controllerlib.WithInitialEvent,
			)
		},
	)
}

func TestCreaterControllerInitialEvent(t *testing.T) {
	kubeSystemInformerClient := kubernetesfake.NewSimpleClientset()
	kubeSystemInformers := kubeinformers.NewSharedInformerFactory(kubeSystemInformerClient, 0)

	agentInformerClient := kubernetesfake.NewSimpleClientset()
	agentInformers := kubeinformers.NewSharedInformerFactory(agentInformerClient, 0)

	observableWithInitialEventOption := testutil.NewObservableWithInitialEventOption()

	_ = NewCreaterController(
		nil, // agentPodConfig, shouldn't matter
		nil, // credentialIssuerConfigLocationConfig, shouldn't matter
		map[string]string{},
		nil, // clock, shouldn't matter
		nil, // k8sClient, shouldn't matter
		nil, // pinnipedAPIClient, shouldn't matter
		kubeSystemInformers.Core().V1().Pods(),
		agentInformers.Core().V1().Pods(),
		controllerlib.WithInformer,
		observableWithInitialEventOption.WithInitialEvent,
	)
	require.Equal(t, &controllerlib.Key{}, observableWithInitialEventOption.GetInitialEventKey())
}

func TestCreaterControllerSync(t *testing.T) {
	spec.Run(t, "CreaterControllerSync", func(t *testing.T, when spec.G, it spec.S) {
		const kubeSystemNamespace = "kube-system"
		const agentPodNamespace = "agent-pod-namespace"
		const credentialIssuerConfigNamespaceName = "cic-namespace-name"
		const credentialIssuerConfigResourceName = "cic-resource-name"

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
		var credentialIssuerConfigGVR schema.GroupVersionResource
		var frozenNow time.Time

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewCreaterController(
				&AgentPodConfig{
					Namespace:                 agentPodNamespace,
					ContainerImage:            "some-agent-image",
					PodNamePrefix:             "some-agent-name-",
					ContainerImagePullSecrets: []string{"some-image-pull-secret"},
					AdditionalLabels: map[string]string{
						"myLabelKey1": "myLabelValue1",
						"myLabelKey2": "myLabelValue2",
					},
				},
				&CredentialIssuerConfigLocationConfig{
					Namespace: credentialIssuerConfigNamespaceName,
					Name:      credentialIssuerConfigResourceName,
				},
				map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				clock.NewFakeClock(frozenNow),
				kubeAPIClient,
				pinnipedAPIClient,
				kubeSystemInformers.Core().V1().Pods(),
				agentInformers.Core().V1().Pods(),
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
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
				kubeSystemNamespace, agentPodNamespace, "ignored for this test", "ignored for this test",
			)

			podsGVR = schema.GroupVersionResource{
				Group:    corev1.SchemeGroupVersion.Group,
				Version:  corev1.SchemeGroupVersion.Version,
				Resource: "pods",
			}

			credentialIssuerConfigGVR = schema.GroupVersionResource{
				Group:    configv1alpha1.GroupName,
				Version:  configv1alpha1.SchemeGroupVersion.Version,
				Resource: "credentialissuerconfigs",
			}

			frozenNow = time.Date(2020, time.September, 23, 7, 42, 0, 0, time.Local)

			// Add a pod into the test that doesn't matter to make sure we don't accidentally trigger any
			// logic on this thing.
			ignorablePod := corev1.Pod{}
			ignorablePod.Name = "some-ignorable-pod"
			r.NoError(kubeSystemInformerClient.Tracker().Add(&ignorablePod))
			r.NoError(kubeAPIClient.Tracker().Add(&ignorablePod))

			// Add another valid agent pod to make sure our logic works for just the pod we care about.
			otherAgentPod := agentPod.DeepCopy()
			otherAgentPod.Name = "some-other-agent"
			otherAgentPod.Annotations = map[string]string{
				"kube-cert-agent.pinniped.dev/controller-manager-name": "some-other-controller-manager-name",
				"kube-cert-agent.pinniped.dev/controller-manager-uid":  "some-other-controller-manager-uid",
			}
			r.NoError(agentInformerClient.Tracker().Add(otherAgentPod))
			r.NoError(kubeAPIClient.Tracker().Add(otherAgentPod))
		})

		it.After(func() {
			timeoutContextCancel()
		})

		when("there is a controller manager pod", func() {
			it.Before(func() {
				r.NoError(kubeSystemInformerClient.Tracker().Add(controllerManagerPod))
				r.NoError(kubeAPIClient.Tracker().Add(controllerManagerPod))
			})

			when("there is a matching agent pod", func() {
				it.Before(func() {
					r.NoError(agentInformerClient.Tracker().Add(agentPod))
					r.NoError(kubeAPIClient.Tracker().Add(agentPod))
				})

				it("does nothing", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Empty(kubeAPIClient.Actions())
				})
			})

			when("there is a matching agent pod that is missing some of the configured additional labels", func() {
				it.Before(func() {
					nonMatchingAgentPod := agentPod.DeepCopy()
					delete(nonMatchingAgentPod.ObjectMeta.Labels, "myLabelKey1")
					r.NoError(agentInformerClient.Tracker().Add(nonMatchingAgentPod))
					r.NoError(kubeAPIClient.Tracker().Add(nonMatchingAgentPod))
				})

				it("does nothing because the deleter controller is responsible for deleting it", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Empty(kubeAPIClient.Actions())
				})
			})

			when("there is a non-matching agent pod", func() {
				it.Before(func() {
					nonMatchingAgentPod := agentPod.DeepCopy()
					nonMatchingAgentPod.Name = "some-agent-name-85da432e"
					nonMatchingAgentPod.Annotations[controllerManagerUIDAnnotationKey] = "some-non-matching-uid"
					r.NoError(agentInformerClient.Tracker().Add(nonMatchingAgentPod))
					r.NoError(kubeAPIClient.Tracker().Add(nonMatchingAgentPod))
				})

				it("creates a matching agent pod", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{
							coretesting.NewCreateAction(
								podsGVR,
								agentPodNamespace,
								agentPod,
							),
						},
						kubeAPIClient.Actions(),
					)
				})
			})

			when("there is no matching agent pod", func() {
				it("creates a matching agent pod", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{
							coretesting.NewCreateAction(
								podsGVR,
								agentPodNamespace,
								agentPod,
							),
						},
						kubeAPIClient.Actions(),
					)
				})

				when("creating the matching agent pod fails", func() {
					it.Before(func() {
						kubeAPIClient.PrependReactor(
							"create",
							"pods",
							func(_ coretesting.Action) (bool, runtime.Object, error) {
								return true, nil, errors.New("some create error")
							},
						)
					})

					when("there is already a CredentialIssuerConfig", func() {
						var initialCredentialIssuerConfig *configv1alpha1.CredentialIssuerConfig

						it.Before(func() {
							initialCredentialIssuerConfig = &configv1alpha1.CredentialIssuerConfig{
								TypeMeta: metav1.TypeMeta{},
								ObjectMeta: metav1.ObjectMeta{
									Name:      credentialIssuerConfigResourceName,
									Namespace: credentialIssuerConfigNamespaceName,
								},
								Status: configv1alpha1.CredentialIssuerConfigStatus{
									Strategies: []configv1alpha1.CredentialIssuerConfigStrategy{},
									KubeConfigInfo: &configv1alpha1.CredentialIssuerConfigKubeConfigInfo{
										Server:                   "some-server",
										CertificateAuthorityData: "some-ca-value",
									},
								},
							}
							r.NoError(pinnipedAPIClient.Tracker().Add(initialCredentialIssuerConfig))
						})

						it("updates the CredentialIssuerConfig status saying that controller manager pods couldn't be found", func() {
							startInformersAndController()
							err := controllerlib.TestSync(t, subject, *syncContext)

							expectedCredentialIssuerConfig := initialCredentialIssuerConfig.DeepCopy()
							expectedCredentialIssuerConfig.Status.Strategies = []configv1alpha1.CredentialIssuerConfigStrategy{
								{
									Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
									Status:         configv1alpha1.ErrorStrategyStatus,
									Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
									Message:        "cannot create agent pod: some create error",
									LastUpdateTime: metav1.NewTime(frozenNow),
								},
							}
							expectedGetAction := coretesting.NewGetAction(
								credentialIssuerConfigGVR,
								credentialIssuerConfigNamespaceName,
								credentialIssuerConfigResourceName,
							)
							expectedUpdateAction := coretesting.NewUpdateAction(
								credentialIssuerConfigGVR,
								credentialIssuerConfigNamespaceName,
								expectedCredentialIssuerConfig,
							)

							r.EqualError(err, "cannot create agent pod: some create error")
							r.Equal(
								[]coretesting.Action{
									expectedGetAction,
									expectedUpdateAction,
								},
								pinnipedAPIClient.Actions(),
							)
						})

						when("the CredentialIssuerConfig operation fails", func() {
							it.Before(func() {
								pinnipedAPIClient.PrependReactor(
									"update",
									"credentialissuerconfigs",
									func(_ coretesting.Action) (bool, runtime.Object, error) {
										return true, nil, errors.New("some update error")
									},
								)

								it("still returns the pod create error, since the controller will get rescheduled", func() {
									startInformersAndController()
									err := controllerlib.TestSync(t, subject, *syncContext)
									r.EqualError(err, "cannot create agent pod: some create error")
								})
							})
						})
					})

					when("there is not already a CredentialIssuerConfig", func() {
						it("returns an error and updates the CredentialIssuerConfig status", func() {
							startInformersAndController()
							err := controllerlib.TestSync(t, subject, *syncContext)

							expectedCredentialIssuerConfig := &configv1alpha1.CredentialIssuerConfig{
								TypeMeta: metav1.TypeMeta{},
								ObjectMeta: metav1.ObjectMeta{
									Name:      credentialIssuerConfigResourceName,
									Namespace: credentialIssuerConfigNamespaceName,
									Labels: map[string]string{
										"myLabelKey1": "myLabelValue1",
										"myLabelKey2": "myLabelValue2",
									},
								},
								Status: configv1alpha1.CredentialIssuerConfigStatus{
									Strategies: []configv1alpha1.CredentialIssuerConfigStrategy{
										{
											Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
											Status:         configv1alpha1.ErrorStrategyStatus,
											Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
											Message:        "cannot create agent pod: some create error",
											LastUpdateTime: metav1.NewTime(frozenNow),
										},
									},
								},
							}
							expectedGetAction := coretesting.NewGetAction(
								credentialIssuerConfigGVR,
								credentialIssuerConfigNamespaceName,
								credentialIssuerConfigResourceName,
							)
							expectedCreateAction := coretesting.NewCreateAction(
								credentialIssuerConfigGVR,
								credentialIssuerConfigNamespaceName,
								expectedCredentialIssuerConfig,
							)

							r.EqualError(err, "cannot create agent pod: some create error")
							r.Equal(
								[]coretesting.Action{
									expectedGetAction,
									expectedCreateAction,
								},
								pinnipedAPIClient.Actions(),
							)
						})
					})
				})
			})
		})

		when("there is no controller manager pod", func() {
			when("there is already a CredentialIssuerConfig", func() {
				var initialCredentialIssuerConfig *configv1alpha1.CredentialIssuerConfig

				it.Before(func() {
					initialCredentialIssuerConfig = &configv1alpha1.CredentialIssuerConfig{
						TypeMeta: metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{
							Name:      credentialIssuerConfigResourceName,
							Namespace: credentialIssuerConfigNamespaceName,
						},
						Status: configv1alpha1.CredentialIssuerConfigStatus{
							Strategies: []configv1alpha1.CredentialIssuerConfigStrategy{},
							KubeConfigInfo: &configv1alpha1.CredentialIssuerConfigKubeConfigInfo{
								Server:                   "some-server",
								CertificateAuthorityData: "some-ca-value",
							},
						},
					}
					r.NoError(pinnipedAPIClient.Tracker().Add(initialCredentialIssuerConfig))
				})

				it("updates the CredentialIssuerConfig status saying that controller manager pods couldn't be found", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					expectedCredentialIssuerConfig := initialCredentialIssuerConfig.DeepCopy()
					expectedCredentialIssuerConfig.Status.Strategies = []configv1alpha1.CredentialIssuerConfigStrategy{
						{
							Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
							Status:         configv1alpha1.ErrorStrategyStatus,
							Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
							Message:        "did not find kube-controller-manager pod(s)",
							LastUpdateTime: metav1.NewTime(frozenNow),
						},
					}
					expectedGetAction := coretesting.NewGetAction(
						credentialIssuerConfigGVR,
						credentialIssuerConfigNamespaceName,
						credentialIssuerConfigResourceName,
					)
					expectedUpdateAction := coretesting.NewUpdateAction(
						credentialIssuerConfigGVR,
						credentialIssuerConfigNamespaceName,
						expectedCredentialIssuerConfig,
					)

					r.Equal(
						[]coretesting.Action{
							expectedGetAction,
							expectedUpdateAction,
						},
						pinnipedAPIClient.Actions(),
					)
				})

				when("when updating the CredentialIssuerConfig fails", func() {
					it.Before(func() {
						pinnipedAPIClient.PrependReactor(
							"update",
							"credentialissuerconfigs",
							func(_ coretesting.Action) (bool, runtime.Object, error) {
								return true, nil, errors.New("some update error")
							},
						)
					})

					it("returns an error", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)
						r.EqualError(err, "could not create or update credentialissuerconfig: some update error")
					})
				})

				when("when getting the CredentialIssuerConfig fails", func() {
					it.Before(func() {
						pinnipedAPIClient.PrependReactor(
							"get",
							"credentialissuerconfigs",
							func(_ coretesting.Action) (bool, runtime.Object, error) {
								return true, nil, errors.New("some get error")
							},
						)
					})

					it("returns an error", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)
						r.EqualError(err, "could not create or update credentialissuerconfig: get failed: some get error")
					})
				})
			})

			when("there is not already a CredentialIssuerConfig", func() {
				it("creates the CredentialIssuerConfig status saying that controller manager pods couldn't be found", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)

					expectedCredentialIssuerConfig := &configv1alpha1.CredentialIssuerConfig{
						TypeMeta: metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{
							Name:      credentialIssuerConfigResourceName,
							Namespace: credentialIssuerConfigNamespaceName,
							Labels: map[string]string{
								"myLabelKey1": "myLabelValue1",
								"myLabelKey2": "myLabelValue2",
							},
						},
						Status: configv1alpha1.CredentialIssuerConfigStatus{
							Strategies: []configv1alpha1.CredentialIssuerConfigStrategy{
								{
									Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
									Status:         configv1alpha1.ErrorStrategyStatus,
									Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
									Message:        "did not find kube-controller-manager pod(s)",
									LastUpdateTime: metav1.NewTime(frozenNow),
								},
							},
						},
					}
					expectedGetAction := coretesting.NewGetAction(
						credentialIssuerConfigGVR,
						credentialIssuerConfigNamespaceName,
						credentialIssuerConfigResourceName,
					)
					expectedCreateAction := coretesting.NewCreateAction(
						credentialIssuerConfigGVR,
						credentialIssuerConfigNamespaceName,
						expectedCredentialIssuerConfig,
					)

					r.NoError(err)
					r.Equal(
						[]coretesting.Action{
							expectedGetAction,
							expectedCreateAction,
						},
						pinnipedAPIClient.Actions(),
					)
				})

				when("when creating the CredentialIssuerConfig fails", func() {
					it.Before(func() {
						pinnipedAPIClient.PrependReactor(
							"create",
							"credentialissuerconfigs",
							func(_ coretesting.Action) (bool, runtime.Object, error) {
								return true, nil, errors.New("some create error")
							},
						)
					})

					it("returns an error", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)
						r.EqualError(err, "could not create or update credentialissuerconfig: create failed: some create error")
					})
				})

				when("when getting the CredentialIssuerConfig fails", func() {
					it.Before(func() {
						pinnipedAPIClient.PrependReactor(
							"get",
							"credentialissuerconfigs",
							func(_ coretesting.Action) (bool, runtime.Object, error) {
								return true, nil, errors.New("some get error")
							},
						)
					})

					it("returns an error", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)
						r.EqualError(err, "could not create or update credentialissuerconfig: get failed: some get error")
					})
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
