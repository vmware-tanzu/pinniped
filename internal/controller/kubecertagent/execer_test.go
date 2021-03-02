// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
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
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/testutil"
)

func TestExecerControllerOptions(t *testing.T) {
	spec.Run(t, "options", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var observableWithInformerOption *testutil.ObservableWithInformerOption
		var agentPodInformerFilter controllerlib.Filter

		whateverPod := &corev1.Pod{}

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			informerFactory := kubeinformers.NewSharedInformerFactory(nil, 0)
			agentPodsInformer := informerFactory.Core().V1().Pods()
			configMapsInformer := informerFactory.Core().V1().ConfigMaps()
			_ = NewExecerController(
				&CredentialIssuerLocationConfig{
					Name: "ignored by this test",
				},
				nil, // credentialIssuerLabels, not needed for this test
				nil, // discoveryURLOverride, not needed for this test
				nil, // dynamicCertProvider, not needed for this test
				nil, // podCommandExecutor, not needed for this test
				nil, // pinnipedAPIClient, not needed for this test
				nil, // clock, not needed for this test
				agentPodsInformer,
				configMapsInformer,
				observableWithInformerOption.WithInformer,
			)
			agentPodInformerFilter = observableWithInformerOption.GetFilterForInformer(agentPodsInformer)
		})

		when("the change is happening in the agent's namespace", func() {
			when("a pod with all agent labels is added/updated/deleted", func() {
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
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}

type fakePodExecutor struct {
	r *require.Assertions

	resultsToReturn []string
	errorsToReturn  []error

	calledWithPodName        []string
	calledWithPodNamespace   []string
	calledWithCommandAndArgs [][]string

	callCount int
}

func (s *fakePodExecutor) Exec(podNamespace string, podName string, commandAndArgs ...string) (string, error) {
	s.calledWithPodNamespace = append(s.calledWithPodNamespace, podNamespace)
	s.calledWithPodName = append(s.calledWithPodName, podName)
	s.calledWithCommandAndArgs = append(s.calledWithCommandAndArgs, commandAndArgs)
	s.r.Less(s.callCount, len(s.resultsToReturn), "unexpected extra invocation of fakePodExecutor")
	result := s.resultsToReturn[s.callCount]
	var err error = nil
	if s.errorsToReturn != nil {
		s.r.Less(s.callCount, len(s.errorsToReturn), "unexpected extra invocation of fakePodExecutor")
		err = s.errorsToReturn[s.callCount]
	}
	s.callCount++
	if err != nil {
		return "", err
	}
	return result, nil
}

func TestManagerControllerSync(t *testing.T) {
	spec.Run(t, "Sync", func(t *testing.T, when spec.G, it spec.S) {
		const agentPodNamespace = "some-namespace"
		const agentPodName = "some-agent-pod-name-123"
		const certPathAnnotationName = "kube-cert-agent.pinniped.dev/cert-path"
		const keyPathAnnotationName = "kube-cert-agent.pinniped.dev/key-path"
		const fakeCertPath = "/some/cert/path"
		const fakeKeyPath = "/some/key/path"
		const defaultDynamicCertProviderCert = "initial-cert"
		const defaultDynamicCertProviderKey = "initial-key"
		const credentialIssuerResourceName = "ci-resource-name"

		var r *require.Assertions

		var subject controllerlib.Controller
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var syncContext *controllerlib.Context
		var pinnipedAPIClient *pinnipedfake.Clientset
		var kubeInformerFactory kubeinformers.SharedInformerFactory
		var kubeClientset *kubernetesfake.Clientset
		var fakeExecutor *fakePodExecutor
		var credentialIssuerLabels map[string]string
		var discoveryURLOverride *string
		var dynamicCertProvider dynamiccert.Provider
		var fakeCertPEM, fakeKeyPEM string
		var credentialIssuerGVR schema.GroupVersionResource
		var frozenNow time.Time

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewExecerController(
				&CredentialIssuerLocationConfig{
					Name: credentialIssuerResourceName,
				},
				credentialIssuerLabels,
				discoveryURLOverride,
				dynamicCertProvider,
				fakeExecutor,
				pinnipedAPIClient,
				clock.NewFakeClock(frozenNow),
				kubeInformerFactory.Core().V1().Pods(),
				kubeInformerFactory.Core().V1().ConfigMaps(),
				controllerlib.WithInformer,
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: timeoutContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Namespace: agentPodNamespace,
					Name:      agentPodName,
				},
			}

			// Must start informers before calling TestRunSynchronously()
			kubeInformerFactory.Start(timeoutContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		var newAgentPod = func(agentPodName string, hasCertPathAnnotations bool) *corev1.Pod {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      agentPodName,
					Namespace: agentPodNamespace,
					Labels: map[string]string{
						"some-label-key": "some-label-value",
					},
				},
			}
			if hasCertPathAnnotations {
				pod.Annotations = map[string]string{
					certPathAnnotationName: fakeCertPath,
					keyPathAnnotationName:  fakeKeyPath,
				}
			}
			return pod
		}

		var requireDynamicCertProviderHasDefaultValues = func() {
			actualCertPEM, actualKeyPEM := dynamicCertProvider.CurrentCertKeyContent()
			r.Equal(defaultDynamicCertProviderCert, string(actualCertPEM))
			r.Equal(defaultDynamicCertProviderKey, string(actualKeyPEM))
		}

		var requireNoExternalActionsTaken = func() {
			r.Empty(pinnipedAPIClient.Actions())
			r.Zero(fakeExecutor.callCount)
			requireDynamicCertProviderHasDefaultValues()
		}

		it.Before(func() {
			r = require.New(t)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)
			pinnipedAPIClient = pinnipedfake.NewSimpleClientset()
			kubeClientset = kubernetesfake.NewSimpleClientset()
			kubeInformerFactory = kubeinformers.NewSharedInformerFactory(kubeClientset, 0)
			fakeExecutor = &fakePodExecutor{r: r}
			frozenNow = time.Date(2020, time.September, 23, 7, 42, 0, 0, time.Local)
			dynamicCertProvider = dynamiccert.New()
			dynamicCertProvider.Set([]byte(defaultDynamicCertProviderCert), []byte(defaultDynamicCertProviderKey))

			loadFile := func(filename string) string {
				bytes, err := ioutil.ReadFile(filename)
				r.NoError(err)
				return string(bytes)
			}
			fakeCertPEM = loadFile("./testdata/test.crt")
			fakeKeyPEM = loadFile("./testdata/test.key")

			credentialIssuerGVR = schema.GroupVersionResource{
				Group:    configv1alpha1.GroupName,
				Version:  configv1alpha1.SchemeGroupVersion.Version,
				Resource: "credentialissuers",
			}
		})

		it.After(func() {
			timeoutContextCancel()
		})

		when("there is not yet any agent pods or they were deleted", func() {
			it.Before(func() {
				unrelatedPod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "some other pod",
						Namespace: agentPodNamespace,
					},
				}
				r.NoError(kubeClientset.Tracker().Add(unrelatedPod))
				startInformersAndController()
			})

			it("does nothing", func() {
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				requireNoExternalActionsTaken()
			})
		})

		when("there is an agent pod, as determined by its labels matching the agent pod template labels, which is not yet annotated by the annotater controller", func() {
			it.Before(func() {
				agentPod := newAgentPod(agentPodName, false)
				r.NoError(kubeClientset.Tracker().Add(agentPod))
				startInformersAndController()
			})

			it("does nothing", func() {
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				requireNoExternalActionsTaken()
			})
		})

		when("there is an agent pod, as determined by its labels matching the agent pod template labels, and it was annotated by the annotater controller, but it is not Running", func() {
			it.Before(func() {
				agentPod := newAgentPod(agentPodName, true)
				agentPod.Status.Phase = corev1.PodPending // not Running
				r.NoError(kubeClientset.Tracker().Add(agentPod))
				startInformersAndController()
			})

			it("does nothing", func() {
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				requireNoExternalActionsTaken()
			})
		})

		when("there is an agent pod, as determined by its labels matching the agent pod template labels, which is already annotated by the annotater controller, and it is Running", func() {
			it.Before(func() {
				targetAgentPod := newAgentPod(agentPodName, true)
				targetAgentPod.Status.Phase = corev1.PodRunning
				anotherAgentPod := newAgentPod("some-other-agent-pod-which-is-not-the-context-of-this-sync", true)
				r.NoError(kubeClientset.Tracker().Add(targetAgentPod))
				r.NoError(kubeClientset.Tracker().Add(anotherAgentPod))
			})

			when("the resulting pod execs will succeed", func() {
				it.Before(func() {
					fakeExecutor.resultsToReturn = []string{fakeCertPEM, fakeKeyPEM}
				})

				when("the cluster-info ConfigMap is not found", func() {
					it("returns an error and updates the strategy with an error", func() {
						startInformersAndController()
						r.EqualError(controllerlib.TestSync(t, subject, *syncContext), `failed to get cluster-info configmap: configmap "cluster-info" not found`)

						expectedCreateCredentialIssuer := &configv1alpha1.CredentialIssuer{
							TypeMeta: metav1.TypeMeta{},
							ObjectMeta: metav1.ObjectMeta{
								Name: credentialIssuerResourceName,
							},
						}

						expectedCredentialIssuer := &configv1alpha1.CredentialIssuer{
							TypeMeta: metav1.TypeMeta{},
							ObjectMeta: metav1.ObjectMeta{
								Name: credentialIssuerResourceName,
							},
							Status: configv1alpha1.CredentialIssuerStatus{
								Strategies: []configv1alpha1.CredentialIssuerStrategy{
									{
										Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
										Status:         configv1alpha1.ErrorStrategyStatus,
										Reason:         configv1alpha1.CouldNotGetClusterInfoStrategyReason,
										Message:        `failed to get cluster-info configmap: configmap "cluster-info" not found`,
										LastUpdateTime: metav1.NewTime(frozenNow),
									},
								},
							},
						}
						expectedGetAction := coretesting.NewRootGetAction(credentialIssuerGVR, credentialIssuerResourceName)
						expectedCreateAction := coretesting.NewRootCreateAction(credentialIssuerGVR, expectedCreateCredentialIssuer)
						expectedUpdateAction := coretesting.NewRootUpdateSubresourceAction(credentialIssuerGVR, "status", expectedCredentialIssuer)
						r.Equal([]coretesting.Action{expectedGetAction, expectedCreateAction, expectedUpdateAction}, pinnipedAPIClient.Actions())
					})
				})

				when("the cluster-info ConfigMap is missing a key", func() {
					it.Before(func() {
						r.NoError(kubeClientset.Tracker().Add(&corev1.ConfigMap{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: ClusterInfoNamespace,
								Name:      clusterInfoName,
							},
							Data: map[string]string{"uninteresting-key": "uninteresting-value"},
						}))
					})
					it("returns an error", func() {
						startInformersAndController()
						r.EqualError(controllerlib.TestSync(t, subject, *syncContext), `failed to get kubeconfig key from cluster-info configmap`)
					})
				})

				when("the cluster-info ConfigMap is contains invalid YAML", func() {
					it.Before(func() {
						r.NoError(kubeClientset.Tracker().Add(&corev1.ConfigMap{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: ClusterInfoNamespace,
								Name:      clusterInfoName,
							},
							Data: map[string]string{"kubeconfig": "invalid-yaml"},
						}))
					})
					it("returns an error", func() {
						startInformersAndController()
						r.EqualError(controllerlib.TestSync(t, subject, *syncContext), `failed to load data from kubeconfig key in cluster-info configmap`)
					})
				})

				when("the cluster-info ConfigMap is contains an empty list of clusters", func() {
					it.Before(func() {
						r.NoError(kubeClientset.Tracker().Add(&corev1.ConfigMap{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: ClusterInfoNamespace,
								Name:      clusterInfoName,
							},
							Data: map[string]string{
								"kubeconfig": here.Doc(`
									kind: Config
									apiVersion: v1
									clusters: []
									`),
								"uninteresting-key": "uninteresting-value",
							},
						}))
					})
					it("returns an error", func() {
						startInformersAndController()
						r.EqualError(controllerlib.TestSync(t, subject, *syncContext), `kubeconfig in kubeconfig key in cluster-info configmap did not contain any clusters`)
					})
				})

				when("the cluster-info ConfigMap is valid", func() {
					it.Before(func() {
						const caData = "c29tZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YQo=" // "some-certificate-authority-data" base64 encoded
						const kubeServerURL = "https://some-server"
						r.NoError(kubeClientset.Tracker().Add(&corev1.ConfigMap{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: ClusterInfoNamespace,
								Name:      clusterInfoName,
							},
							Data: map[string]string{
								"kubeconfig": here.Docf(`
									kind: Config
									apiVersion: v1
									clusters:
									- name: ""
									  cluster:
										certificate-authority-data: "%s"
										server: "%s"`,
									caData, kubeServerURL),
								"uninteresting-key": "uninteresting-value",
							},
						}))
					})

					it("execs to the agent pod to get the keys and updates the dynamic certificates provider with the new certs", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))

						r.Equal(2, fakeExecutor.callCount)

						r.Equal(agentPodNamespace, fakeExecutor.calledWithPodNamespace[0])
						r.Equal(agentPodName, fakeExecutor.calledWithPodName[0])
						r.Equal([]string{"cat", fakeCertPath}, fakeExecutor.calledWithCommandAndArgs[0])

						r.Equal(agentPodNamespace, fakeExecutor.calledWithPodNamespace[1])
						r.Equal(agentPodName, fakeExecutor.calledWithPodName[1])
						r.Equal([]string{"cat", fakeKeyPath}, fakeExecutor.calledWithCommandAndArgs[1])

						actualCertPEM, actualKeyPEM := dynamicCertProvider.CurrentCertKeyContent()
						r.Equal(fakeCertPEM, string(actualCertPEM))
						r.Equal(fakeKeyPEM, string(actualKeyPEM))
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

						it("also updates the the existing CredentialIssuer status field", func() {
							startInformersAndController()
							r.NoError(controllerlib.TestSync(t, subject, *syncContext))

							// The first update to the CredentialIssuer will set the strategy entry
							expectedCredentialIssuer := initialCredentialIssuer.DeepCopy()
							expectedCredentialIssuer.Status.Strategies = []configv1alpha1.CredentialIssuerStrategy{
								{
									Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
									Status:         configv1alpha1.SuccessStrategyStatus,
									Reason:         configv1alpha1.FetchedKeyStrategyReason,
									Message:        "Key was fetched successfully",
									LastUpdateTime: metav1.NewTime(frozenNow),
									Frontend: &configv1alpha1.CredentialIssuerFrontend{
										Type: configv1alpha1.TokenCredentialRequestAPIFrontendType,
										TokenCredentialRequestAPIInfo: &configv1alpha1.TokenCredentialRequestAPIInfo{
											Server:                   "https://some-server",
											CertificateAuthorityData: "c29tZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YQo=",
										},
									},
								},
							}
							expectedCredentialIssuer.Status.KubeConfigInfo = &configv1alpha1.CredentialIssuerKubeConfigInfo{
								Server:                   "https://some-server",
								CertificateAuthorityData: "c29tZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YQo=",
							}
							expectedGetAction := coretesting.NewRootGetAction(credentialIssuerGVR, credentialIssuerResourceName)
							expectedCreateAction := coretesting.NewRootUpdateSubresourceAction(credentialIssuerGVR, "status", expectedCredentialIssuer)
							r.Equal([]coretesting.Action{expectedGetAction, expectedCreateAction}, pinnipedAPIClient.Actions())
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

							it("returns an error", func() {
								startInformersAndController()
								err := controllerlib.TestSync(t, subject, *syncContext)
								r.EqualError(err, "could not create or update credentialissuer: some update error")
							})
						})
					})

					when("there is not already a CredentialIssuer", func() {
						it.Before(func() {
							server := "https://overridden-server-url.example.com"
							discoveryURLOverride = &server
							credentialIssuerLabels = map[string]string{"foo": "bar"}
							startInformersAndController()
						})

						it("also creates the the CredentialIssuer with the appropriate status field and labels", func() {
							r.NoError(controllerlib.TestSync(t, subject, *syncContext))

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
											Status:         configv1alpha1.SuccessStrategyStatus,
											Reason:         configv1alpha1.FetchedKeyStrategyReason,
											Message:        "Key was fetched successfully",
											LastUpdateTime: metav1.NewTime(frozenNow),
											Frontend: &configv1alpha1.CredentialIssuerFrontend{
												Type: configv1alpha1.TokenCredentialRequestAPIFrontendType,
												TokenCredentialRequestAPIInfo: &configv1alpha1.TokenCredentialRequestAPIInfo{
													Server:                   "https://overridden-server-url.example.com",
													CertificateAuthorityData: "c29tZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YQo=",
												},
											},
										},
									},
									KubeConfigInfo: &configv1alpha1.CredentialIssuerKubeConfigInfo{
										Server:                   "https://overridden-server-url.example.com",
										CertificateAuthorityData: "c29tZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YQo=",
									},
								},
							}
							expectedGetAction := coretesting.NewRootGetAction(credentialIssuerGVR, credentialIssuerResourceName)
							expectedCreateAction := coretesting.NewRootCreateAction(credentialIssuerGVR, expectedCreateCredentialIssuer)
							expectedUpdateAction := coretesting.NewRootUpdateSubresourceAction(credentialIssuerGVR, "status", expectedCredentialIssuer)
							r.Equal([]coretesting.Action{expectedGetAction, expectedCreateAction, expectedUpdateAction}, pinnipedAPIClient.Actions())
						})
					})
				})
			})

			when("the first resulting pod exec will fail", func() {
				var podExecErrorMessage string

				it.Before(func() {
					podExecErrorMessage = "some pod exec error message"
					fakeExecutor.errorsToReturn = []error{fmt.Errorf(podExecErrorMessage), nil}
					fakeExecutor.resultsToReturn = []string{"", fakeKeyPEM}
					startInformersAndController()
				})

				it("does not update the dynamic certificates provider", func() {
					r.EqualError(controllerlib.TestSync(t, subject, *syncContext), podExecErrorMessage)
					requireDynamicCertProviderHasDefaultValues()
				})

				it("creates or updates the the CredentialIssuer status field with an error", func() {
					r.EqualError(controllerlib.TestSync(t, subject, *syncContext), podExecErrorMessage)

					expectedCreateCredentialIssuer := &configv1alpha1.CredentialIssuer{
						TypeMeta: metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{
							Name: credentialIssuerResourceName,
						},
					}

					expectedCredentialIssuer := &configv1alpha1.CredentialIssuer{
						TypeMeta: metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{
							Name: credentialIssuerResourceName,
						},
						Status: configv1alpha1.CredentialIssuerStatus{
							Strategies: []configv1alpha1.CredentialIssuerStrategy{
								{
									Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
									Status:         configv1alpha1.ErrorStrategyStatus,
									Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
									Message:        podExecErrorMessage,
									LastUpdateTime: metav1.NewTime(frozenNow),
								},
							},
						},
					}
					expectedGetAction := coretesting.NewRootGetAction(credentialIssuerGVR, credentialIssuerResourceName)
					expectedCreateAction := coretesting.NewRootCreateAction(credentialIssuerGVR, expectedCreateCredentialIssuer)
					expectedUpdateAction := coretesting.NewRootUpdateSubresourceAction(credentialIssuerGVR, "status", expectedCredentialIssuer)
					r.Equal([]coretesting.Action{expectedGetAction, expectedCreateAction, expectedUpdateAction}, pinnipedAPIClient.Actions())
				})
			})

			when("the second resulting pod exec will fail", func() {
				var podExecErrorMessage string

				it.Before(func() {
					podExecErrorMessage = "some pod exec error message"
					fakeExecutor.errorsToReturn = []error{nil, fmt.Errorf(podExecErrorMessage)}
					fakeExecutor.resultsToReturn = []string{fakeCertPEM, ""}
					startInformersAndController()
				})

				it("does not update the dynamic certificates provider", func() {
					r.EqualError(controllerlib.TestSync(t, subject, *syncContext), podExecErrorMessage)
					requireDynamicCertProviderHasDefaultValues()
				})

				it("creates or updates the the CredentialIssuer status field with an error", func() {
					r.EqualError(controllerlib.TestSync(t, subject, *syncContext), podExecErrorMessage)

					expectedCreateCredentialIssuer := &configv1alpha1.CredentialIssuer{
						TypeMeta: metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{
							Name: credentialIssuerResourceName,
						},
					}

					expectedCredentialIssuer := &configv1alpha1.CredentialIssuer{
						TypeMeta: metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{
							Name: credentialIssuerResourceName,
						},
						Status: configv1alpha1.CredentialIssuerStatus{
							Strategies: []configv1alpha1.CredentialIssuerStrategy{
								{
									Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
									Status:         configv1alpha1.ErrorStrategyStatus,
									Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
									Message:        podExecErrorMessage,
									LastUpdateTime: metav1.NewTime(frozenNow),
								},
							},
						},
					}
					expectedGetAction := coretesting.NewRootGetAction(credentialIssuerGVR, credentialIssuerResourceName)
					expectedCreateAction := coretesting.NewRootCreateAction(credentialIssuerGVR, expectedCreateCredentialIssuer)
					expectedUpdateAction := coretesting.NewRootUpdateSubresourceAction(credentialIssuerGVR, "status", expectedCredentialIssuer)
					r.Equal([]coretesting.Action{expectedGetAction, expectedCreateAction, expectedUpdateAction}, pinnipedAPIClient.Actions())
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
