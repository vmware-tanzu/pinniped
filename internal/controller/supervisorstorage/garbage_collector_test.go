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
				nil,
				secretsInformer,
				observableWithInformerOption.WithInformer, // make it possible to observe the behavior of the Filters
			)
			secretsInformerFilter = observableWithInformerOption.GetFilterForInformer(secretsInformer)
		})

		when("watching Secret objects", func() {
			var (
				subject             controllerlib.Filter
				secret, otherSecret *corev1.Secret
			)

			it.Before(func() {
				subject = secretsInformerFilter
				secret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "any-name", Namespace: "any-namespace"}}
				otherSecret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "any-other-name", Namespace: "any-other-namespace"}}
			})

			when("any Secret changes", func() {
				it("returns false to avoid triggering the sync function", func() {
					r.False(subject.Add(secret))
					r.False(subject.Update(secret, otherSecret))
					r.False(subject.Update(otherSecret, secret))
					r.False(subject.Delete(secret))
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

	firstExpiredTime := time.Date(1900, time.January, 1, 1, 0, 0, 0, time.UTC).Format(time.RFC3339)
	secondExpiredTime := time.Date(1901, time.January, 1, 1, 0, 0, 0, time.UTC).Format(time.RFC3339)
	unexpiredTime := time.Now().Add(time.Hour * 24).UTC().Format(time.RFC3339)

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
		)

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = GarbageCollectorController(
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
							"storage.pinniped.dev/garbage-collect-after": firstExpiredTime,
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
							"storage.pinniped.dev/garbage-collect-after": secondExpiredTime,
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
							"storage.pinniped.dev/garbage-collect-after": unexpiredTime,
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
							"storage.pinniped.dev/garbage-collect-after": firstExpiredTime,
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

		when("the delete call fails", func() {
			it.Before(func() {
				erroringSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "erroring secret",
						Namespace: installedInNamespace,
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": firstExpiredTime,
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
							"storage.pinniped.dev/garbage-collect-after": firstExpiredTime,
						},
					},
				}
				r.NoError(kubeInformerClient.Tracker().Add(expiredSecret))
				r.NoError(kubeClient.Tracker().Add(expiredSecret))
			})

			it("continues on to delete the next one", func() {
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
