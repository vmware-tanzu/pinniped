// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"context"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/1.19/client/clientset/versioned/fake"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/provider"
	"go.pinniped.dev/internal/testutil"
)

type fakeCurrentTimeProvider struct {
	frozenNow *metav1.Time
}

func (f *fakeCurrentTimeProvider) Now() metav1.Time {
	if f.frozenNow == nil {
		realNow := metav1.Now()
		f.frozenNow = &realNow
	}
	return *f.frozenNow
}

func TestExecerControllerOptions(t *testing.T) {
	spec.Run(t, "options", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var observableWithInformerOption *testutil.ObservableWithInformerOption
		var agentPodInformerFilter controllerlib.Filter

		whateverPod := &corev1.Pod{}

		agentPodTemplate := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "some-agent-name-ignored",
				Namespace: "some-namespace-ignored",
				Labels: map[string]string{
					"some-label-key": "some-label-value",
				},
			},
			Spec: corev1.PodSpec{},
		}

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			agentPodsInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().Pods()
			_ = NewExecerController(
				&Info{
					Template: agentPodTemplate,
				},
				"credentialIssuerConfigNamespaceName",
				"credentialIssuerConfigResourceName",
				nil, // not needed for this test
				nil, // not needed for this test
				nil, // not needed for this test
				&fakeCurrentTimeProvider{},
				agentPodsInformer,
				observableWithInformerOption.WithInformer,
			)
			agentPodInformerFilter = observableWithInformerOption.GetFilterForInformer(agentPodsInformer)
		})

		when("the change is happening in the agent's namespace", func() {
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

					r.True(agentPodInformerFilter.Add(pod))
					r.True(agentPodInformerFilter.Update(whateverPod, pod))
					r.True(agentPodInformerFilter.Update(pod, whateverPod))
					r.True(agentPodInformerFilter.Delete(pod))
				})
			})

			when("a pod missing any of the agent labels is added/updated/deleted", func() {
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
		const certPathAnnotationName = "cert-path-annotation-name"
		const keyPathAnnotationName = "key-path-annotation-name"
		const fakeCertPath = "/some/cert/path"
		const fakeKeyPath = "/some/key/path"
		const defaultDynamicCertProviderCert = "initial-cert"
		const defaultDynamicCertProviderKey = "initial-key"
		const credentialIssuerConfigNamespaceName = "cic-namespace-name"
		const credentialIssuerConfigResourceName = "cic-resource-name"

		var r *require.Assertions

		var subject controllerlib.Controller
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var syncContext *controllerlib.Context
		var pinnipedAPIClient *pinnipedfake.Clientset
		var agentPodInformer kubeinformers.SharedInformerFactory
		var agentPodInformerClient *kubernetesfake.Clientset
		var fakeExecutor *fakePodExecutor
		var agentPodTemplate *corev1.Pod
		var dynamicCertProvider provider.DynamicTLSServingCertProvider
		var fakeCertPEM, fakeKeyPEM string
		var fakeNow *fakeCurrentTimeProvider
		var credentialIssuerConfigGVR schema.GroupVersionResource

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewExecerController(
				&Info{
					Template:           agentPodTemplate,
					CertPathAnnotation: certPathAnnotationName,
					KeyPathAnnotation:  keyPathAnnotationName,
				},
				credentialIssuerConfigNamespaceName,
				credentialIssuerConfigResourceName,
				dynamicCertProvider,
				fakeExecutor,
				pinnipedAPIClient,
				fakeNow,
				agentPodInformer.Core().V1().Pods(),
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
			agentPodInformer.Start(timeoutContext.Done())
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
			agentPodInformerClient = kubernetesfake.NewSimpleClientset()
			agentPodInformer = kubeinformers.NewSharedInformerFactory(agentPodInformerClient, 0)
			fakeExecutor = &fakePodExecutor{r: r}
			fakeNow = &fakeCurrentTimeProvider{}
			fakeNow.Now() // call once to initialize
			dynamicCertProvider = provider.NewDynamicTLSServingCertProvider()
			dynamicCertProvider.Set([]byte(defaultDynamicCertProviderCert), []byte(defaultDynamicCertProviderKey))

			loadFile := func(filename string) string {
				bytes, err := ioutil.ReadFile(filename)
				r.NoError(err)
				return string(bytes)
			}
			fakeCertPEM = loadFile("./testdata/test.crt")
			fakeKeyPEM = loadFile("./testdata/test.key")

			agentPodTemplate = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-agent-pod-name-",
					Namespace: agentPodNamespace,
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

			credentialIssuerConfigGVR = schema.GroupVersionResource{
				Group:    configv1alpha1.GroupName,
				Version:  configv1alpha1.SchemeGroupVersion.Version,
				Resource: "credentialissuerconfigs",
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
				r.NoError(agentPodInformerClient.Tracker().Add(unrelatedPod))
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
				r.NoError(agentPodInformerClient.Tracker().Add(agentPod))
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
				r.NoError(agentPodInformerClient.Tracker().Add(agentPod))
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
				r.NoError(agentPodInformerClient.Tracker().Add(targetAgentPod))
				r.NoError(agentPodInformerClient.Tracker().Add(anotherAgentPod))
			})

			when("the resulting pod execs will succeed", func() {
				it.Before(func() {
					fakeExecutor.resultsToReturn = []string{fakeCertPEM, fakeKeyPEM}
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

					it("also updates the the existing CredentialIssuerConfig status field", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))

						expectedCredentialIssuerConfig := initialCredentialIssuerConfig.DeepCopy()
						expectedCredentialIssuerConfig.Status.Strategies = []configv1alpha1.CredentialIssuerConfigStrategy{
							{
								Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
								Status:         configv1alpha1.SuccessStrategyStatus,
								Reason:         configv1alpha1.FetchedKeyStrategyReason,
								Message:        "Key was fetched successfully",
								LastUpdateTime: fakeNow.Now(),
							},
						}
						expectedGetAction := coretesting.NewGetAction(credentialIssuerConfigGVR, credentialIssuerConfigNamespaceName, credentialIssuerConfigResourceName)
						expectedCreateAction := coretesting.NewUpdateAction(credentialIssuerConfigGVR, credentialIssuerConfigNamespaceName, expectedCredentialIssuerConfig)
						r.Equal([]coretesting.Action{expectedGetAction, expectedCreateAction}, pinnipedAPIClient.Actions())
					})
				})

				when("there is not already a CredentialIssuerConfig", func() {
					it.Before(func() {
						startInformersAndController()
					})

					it("also creates the the CredentialIssuerConfig with the appropriate status field", func() {
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))

						expectedCredentialIssuerConfig := &configv1alpha1.CredentialIssuerConfig{
							TypeMeta: metav1.TypeMeta{},
							ObjectMeta: metav1.ObjectMeta{
								Name:      credentialIssuerConfigResourceName,
								Namespace: credentialIssuerConfigNamespaceName,
							},
							Status: configv1alpha1.CredentialIssuerConfigStatus{
								Strategies: []configv1alpha1.CredentialIssuerConfigStrategy{
									{
										Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
										Status:         configv1alpha1.SuccessStrategyStatus,
										Reason:         configv1alpha1.FetchedKeyStrategyReason,
										Message:        "Key was fetched successfully",
										LastUpdateTime: fakeNow.Now(),
									},
								},
							},
						}
						expectedGetAction := coretesting.NewGetAction(credentialIssuerConfigGVR, credentialIssuerConfigNamespaceName, credentialIssuerConfigResourceName)
						expectedCreateAction := coretesting.NewCreateAction(credentialIssuerConfigGVR, credentialIssuerConfigNamespaceName, expectedCredentialIssuerConfig)
						r.Equal([]coretesting.Action{expectedGetAction, expectedCreateAction}, pinnipedAPIClient.Actions())
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

				it("creates or updates the the CredentialIssuerConfig status field with an error", func() {
					r.EqualError(controllerlib.TestSync(t, subject, *syncContext), podExecErrorMessage)

					expectedCredentialIssuerConfig := &configv1alpha1.CredentialIssuerConfig{
						TypeMeta: metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{
							Name:      credentialIssuerConfigResourceName,
							Namespace: credentialIssuerConfigNamespaceName,
						},
						Status: configv1alpha1.CredentialIssuerConfigStatus{
							Strategies: []configv1alpha1.CredentialIssuerConfigStrategy{
								{
									Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
									Status:         configv1alpha1.ErrorStrategyStatus,
									Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
									Message:        podExecErrorMessage,
									LastUpdateTime: metav1.Now(),
								},
							},
						},
					}
					expectedGetAction := coretesting.NewGetAction(credentialIssuerConfigGVR, credentialIssuerConfigNamespaceName, credentialIssuerConfigResourceName)
					expectedCreateAction := coretesting.NewCreateAction(credentialIssuerConfigGVR, credentialIssuerConfigNamespaceName, expectedCredentialIssuerConfig)
					r.Equal([]coretesting.Action{expectedGetAction, expectedCreateAction}, pinnipedAPIClient.Actions())
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

				it("creates or updates the the CredentialIssuerConfig status field with an error", func() {
					r.EqualError(controllerlib.TestSync(t, subject, *syncContext), podExecErrorMessage)

					expectedCredentialIssuerConfig := &configv1alpha1.CredentialIssuerConfig{
						TypeMeta: metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{
							Name:      credentialIssuerConfigResourceName,
							Namespace: credentialIssuerConfigNamespaceName,
						},
						Status: configv1alpha1.CredentialIssuerConfigStatus{
							Strategies: []configv1alpha1.CredentialIssuerConfigStrategy{
								{
									Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
									Status:         configv1alpha1.ErrorStrategyStatus,
									Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
									Message:        podExecErrorMessage,
									LastUpdateTime: metav1.Now(),
								},
							},
						},
					}
					expectedGetAction := coretesting.NewGetAction(credentialIssuerConfigGVR, credentialIssuerConfigNamespaceName, credentialIssuerConfigResourceName)
					expectedCreateAction := coretesting.NewCreateAction(credentialIssuerConfigGVR, credentialIssuerConfigNamespaceName, expectedCredentialIssuerConfig)
					r.Equal([]coretesting.Action{expectedGetAction, expectedCreateAction}, pinnipedAPIClient.Actions())
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
