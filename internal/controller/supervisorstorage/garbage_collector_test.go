// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorstorage

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
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func TestGarbageCollectorControllerInformerFilters(t *testing.T) {
	spec.Run(t, "informer filters", func(t *testing.T, when spec.G, it spec.S) {
		var (
			r                            *require.Assertions
			observableWithInformerOption *testutil.ObservableWithInformerOption
			secretsInformerFilter        controllerlib.Filter
		)

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			secretsInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().Secrets()
			_ = GarbageCollectorController(
				clock.RealClock{},
				nil,
				secretsInformer,
				observableWithInformerOption.WithInformer, // make it possible to observe the behavior of the Filters
			)
			secretsInformerFilter = observableWithInformerOption.GetFilterForInformer(secretsInformer)
		})

		when("watching Secret objects", func() {
			var (
				subject                           controllerlib.Filter
				secretWithAnnotation, otherSecret *corev1.Secret
			)

			it.Before(func() {
				subject = secretsInformerFilter
				secretWithAnnotation = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "any-name", Namespace: "any-namespace", Annotations: map[string]string{
					"storage.pinniped.dev/garbage-collect-after": "some timestamp",
				}}}
				otherSecret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "any-other-name", Namespace: "any-namespace"}}
			})

			when("any Secret with the required annotation is added or updated", func() {
				it("returns true to trigger the sync function", func() {
					r.True(subject.Add(secretWithAnnotation))
					r.True(subject.Update(secretWithAnnotation, otherSecret))
					r.True(subject.Update(otherSecret, secretWithAnnotation))
				})
			})

			when("any Secret with the required annotation is deleted", func() {
				it("returns false to skip the sync function because it does not need to worry about secrets that are already gone", func() {
					r.False(subject.Delete(secretWithAnnotation))
				})
			})

			when("any Secret without the required annotation changes", func() {
				it("returns false to skip the sync function", func() {
					r.False(subject.Add(otherSecret))
					r.False(subject.Update(otherSecret, otherSecret))
					r.False(subject.Delete(otherSecret))
				})
			})

			when("any other type is passed", func() {
				it("returns false to skip the sync function", func() {
					wrongType := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "some-ns", Namespace: "some-ns"}}

					r.False(subject.Add(wrongType))
					r.False(subject.Update(wrongType, wrongType))
					r.False(subject.Delete(wrongType))
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}

func TestGarbageCollectorControllerSync(t *testing.T) {
	secretsGVR := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "secrets",
	}

	spec.Run(t, "Sync", func(t *testing.T, when spec.G, it spec.S) {
		const (
			installedInNamespace = "some-namespace"
		)

		var (
			r                    *require.Assertions
			subject              controllerlib.Controller
			kubeInformerClient   *kubernetesfake.Clientset
			kubeClient           *kubernetesfake.Clientset
			kubeInformers        kubeinformers.SharedInformerFactory
			timeoutContext       context.Context
			timeoutContextCancel context.CancelFunc
			syncContext          *controllerlib.Context
			fakeClock            *clock.FakeClock
			frozenNow            time.Time
		)

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = GarbageCollectorController(
				fakeClock,
				kubeClient,
				kubeInformers.Core().V1().Secrets(),
				controllerlib.WithInformer,
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: timeoutContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Namespace: "",
					Name:      "",
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
			kubeClient = kubernetesfake.NewSimpleClientset()
			kubeInformers = kubeinformers.NewSharedInformerFactory(kubeInformerClient, 0)
			frozenNow = time.Now().UTC()
			fakeClock = clock.NewFakeClock(frozenNow)

			unrelatedSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some other unrelated secret",
					Namespace: installedInNamespace,
				},
			}
			r.NoError(kubeInformerClient.Tracker().Add(unrelatedSecret))
			r.NoError(kubeClient.Tracker().Add(unrelatedSecret))
		})

		it.After(func() {
			timeoutContextCancel()
		})

		when("there are secrets without the garbage-collect-after annotation", func() {
			it("does not delete those secrets", func() {
				startInformersAndController()
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				require.Empty(t, kubeClient.Actions())
				list, err := kubeClient.CoreV1().Secrets(installedInNamespace).List(context.Background(), metav1.ListOptions{})
				r.NoError(err)
				r.Len(list.Items, 1)
				r.Equal("some other unrelated secret", list.Items[0].Name)
			})
		})

		when("there are secrets with the garbage-collect-after annotation", func() {
			it.Before(func() {
				firstExpiredSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "first expired secret",
						Namespace: installedInNamespace,
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
					},
				}
				r.NoError(kubeInformerClient.Tracker().Add(firstExpiredSecret))
				r.NoError(kubeClient.Tracker().Add(firstExpiredSecret))
				secondExpiredSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "second expired secret",
						Namespace: installedInNamespace,
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-2 * time.Second).Format(time.RFC3339),
						},
					},
				}
				r.NoError(kubeInformerClient.Tracker().Add(secondExpiredSecret))
				r.NoError(kubeClient.Tracker().Add(secondExpiredSecret))
				unexpiredSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "unexpired secret",
						Namespace: installedInNamespace,
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(time.Second).Format(time.RFC3339),
						},
					},
				}
				r.NoError(kubeInformerClient.Tracker().Add(unexpiredSecret))
				r.NoError(kubeClient.Tracker().Add(unexpiredSecret))
			})

			it("should delete any that are past their expiration", func() {
				startInformersAndController()
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteAction(secretsGVR, installedInNamespace, "first expired secret"),
						kubetesting.NewDeleteAction(secretsGVR, installedInNamespace, "second expired secret"),
					},
					kubeClient.Actions(),
				)
				list, err := kubeClient.CoreV1().Secrets(installedInNamespace).List(context.Background(), metav1.ListOptions{})
				r.NoError(err)
				r.Len(list.Items, 2)
				r.ElementsMatch([]string{"unexpired secret", "some other unrelated secret"}, []string{list.Items[0].Name, list.Items[1].Name})
			})
		})

		when("very little time has passed since the previous sync call", func() {
			it.Before(func() {
				// Add a secret that will expire in 20 seconds.
				expiredSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "expired secret",
						Namespace: installedInNamespace,
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(20 * time.Second).Format(time.RFC3339),
						},
					},
				}
				r.NoError(kubeInformerClient.Tracker().Add(expiredSecret))
				r.NoError(kubeClient.Tracker().Add(expiredSecret))
			})

			it("should do nothing to avoid being super chatty since it is called for every change to any Secret, until more time has passed", func() {
				startInformersAndController()
				require.Empty(t, kubeClient.Actions())

				// Run sync once with the current time set to frozenTime.
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				require.Empty(t, kubeClient.Actions())

				// Run sync again when not enough time has passed since the most recent run, so no delete
				// operations should happen even though there is a expired secret now.
				fakeClock.Step(29 * time.Second)
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				require.Empty(t, kubeClient.Actions())

				// Step to the exact threshold and run Sync again. Now we are past the rate limiting period.
				fakeClock.Step(1*time.Second + 1*time.Millisecond)
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				// It should have deleted the expired secret.
				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteAction(secretsGVR, installedInNamespace, "expired secret"),
					},
					kubeClient.Actions(),
				)
				list, err := kubeClient.CoreV1().Secrets(installedInNamespace).List(context.Background(), metav1.ListOptions{})
				r.NoError(err)
				r.Len(list.Items, 1)
				r.Equal("some other unrelated secret", list.Items[0].Name)
			})
		})

		when("there is a secret with a malformed garbage-collect-after date", func() {
			it.Before(func() {
				malformedSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "malformed secret",
						Namespace: installedInNamespace,
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": "not-a-real-date-string",
						},
					},
				}
				r.NoError(kubeInformerClient.Tracker().Add(malformedSecret))
				r.NoError(kubeClient.Tracker().Add(malformedSecret))
				expiredSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "expired secret",
						Namespace: installedInNamespace,
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
					},
				}
				r.NoError(kubeInformerClient.Tracker().Add(expiredSecret))
				r.NoError(kubeClient.Tracker().Add(expiredSecret))
			})

			it("does not delete that secret", func() {
				startInformersAndController()
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteAction(secretsGVR, installedInNamespace, "expired secret"),
					},
					kubeClient.Actions(),
				)
				list, err := kubeClient.CoreV1().Secrets(installedInNamespace).List(context.Background(), metav1.ListOptions{})
				r.NoError(err)
				r.Len(list.Items, 2)
				r.ElementsMatch([]string{"malformed secret", "some other unrelated secret"}, []string{list.Items[0].Name, list.Items[1].Name})
			})
		})

		when("the kube API delete call fails", func() {
			it.Before(func() {
				erroringSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "erroring secret",
						Namespace: installedInNamespace,
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
					},
				}
				r.NoError(kubeInformerClient.Tracker().Add(erroringSecret))
				r.NoError(kubeClient.Tracker().Add(erroringSecret))
				kubeClient.PrependReactor("delete", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
					if action.(kubetesting.DeleteActionImpl).Name == "erroring secret" {
						return true, nil, errors.New("delete failed: some delete error")
					}
					return false, nil, nil
				})
				expiredSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "expired secret",
						Namespace: installedInNamespace,
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
					},
				}
				r.NoError(kubeInformerClient.Tracker().Add(expiredSecret))
				r.NoError(kubeClient.Tracker().Add(expiredSecret))
			})

			it("ignores the error and continues on to delete the next expired Secret", func() {
				startInformersAndController()
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteAction(secretsGVR, installedInNamespace, "erroring secret"),
						kubetesting.NewDeleteAction(secretsGVR, installedInNamespace, "expired secret"),
					},
					kubeClient.Actions(),
				)
				list, err := kubeClient.CoreV1().Secrets(installedInNamespace).List(context.Background(), metav1.ListOptions{})
				r.NoError(err)
				r.Len(list.Items, 2)
				r.ElementsMatch([]string{"erroring secret", "some other unrelated secret"}, []string{list.Items[0].Name, list.Items[1].Name})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
