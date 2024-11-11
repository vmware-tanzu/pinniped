// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/clientregistry"
	"go.pinniped.dev/internal/federationdomain/dynamicupstreamprovider"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/fositestorage/accesstoken"
	"go.pinniped.dev/internal/fositestorage/authorizationcode"
	"go.pinniped.dev/internal/fositestorage/refreshtoken"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/internal/testutil/testidplister"
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
			secretsInformer := k8sinformers.NewSharedInformerFactory(nil, 0).Core().V1().Secrets()
			_ = GarbageCollectorController(
				nil,
				clock.RealClock{},
				nil,
				secretsInformer,
				observableWithInformerOption.WithInformer, // make it possible to observe the behavior of the Filters
				plog.New(),
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

				it("returns the same singleton key", func() {
					r.Equal(controllerlib.Key{}, subject.Parent(secretWithAnnotation))
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
			installedInNamespace         = "some-namespace"
			currentSessionStorageVersion = "8" // update this when you update the storage version in the production code
		)

		var (
			r                       *require.Assertions
			subject                 controllerlib.Controller
			kubeInformerClient      *kubernetesfake.Clientset
			kubeClient              *kubernetesfake.Clientset
			kubeInformers           k8sinformers.SharedInformerFactory
			cancelContext           context.Context
			cancelContextCancelFunc context.CancelFunc
			syncContext             *controllerlib.Context
			fakeClock               *clocktesting.FakeClock
			frozenNow               time.Time
			auditLog                *bytes.Buffer
			wantAuditLogs           []testutil.WantedAuditLog
		)

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func(idpCache dynamicupstreamprovider.DynamicUpstreamIDPProvider) {
			// Set this at the last second to allow for injection of server override.
			var auditLogger plog.AuditLogger
			auditLogger, auditLog = plog.TestLogger(t)
			subject = GarbageCollectorController(
				idpCache,
				fakeClock,
				kubeClient,
				kubeInformers.Core().V1().Secrets(),
				controllerlib.WithInformer,
				auditLogger,
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: cancelContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Namespace: "foo",
					Name:      "bar",
				},
				Queue: &testQueue{t: t},
			}

			// Must start informers before calling TestRunSynchronously()
			kubeInformers.Start(cancelContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		it.Before(func() {
			r = require.New(t)

			cancelContext, cancelContextCancelFunc = context.WithCancel(context.Background())

			kubeInformerClient = kubernetesfake.NewSimpleClientset()
			kubeClient = kubernetesfake.NewSimpleClientset()
			kubeInformers = k8sinformers.NewSharedInformerFactory(kubeInformerClient, 0)
			frozenNow = time.Now().UTC()
			fakeClock = clocktesting.NewFakeClock(frozenNow)

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
			cancelContextCancelFunc()

			testutil.CompareAuditLogs(t, wantAuditLogs, auditLog.String())
		})

		when("there are secrets without the garbage-collect-after annotation", func() {
			it("does not delete those secrets", func() {
				startInformersAndController(nil)
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				require.Empty(t, kubeClient.Actions())
				list, err := kubeClient.CoreV1().Secrets(installedInNamespace).List(context.Background(), metav1.ListOptions{})
				r.NoError(err)
				r.Len(list.Items, 1)
				r.Equal("some other unrelated secret", list.Items[0].Name)
			})
		})

		when("there are any secrets with the garbage-collect-after annotation", func() {
			it.Before(func() {
				firstExpiredSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "first expired secret",
						Namespace:       installedInNamespace,
						UID:             "uid-123",
						ResourceVersion: "rv-456",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
					},
				}
				r.NoError(kubeInformerClient.Tracker().Add(firstExpiredSecret))
				r.NoError(kubeClient.Tracker().Add(firstExpiredSecret))
				secondExpiredSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "second expired secret",
						Namespace:       installedInNamespace,
						UID:             "uid-789",
						ResourceVersion: "rv-555",
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
				startInformersAndController(nil)
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "first expired secret", testutil.NewPreconditions("uid-123", "rv-456")),
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "second expired secret", testutil.NewPreconditions("uid-789", "rv-555")),
					},
					kubeClient.Actions(),
				)
				list, err := kubeClient.CoreV1().Secrets(installedInNamespace).List(context.Background(), metav1.ListOptions{})
				r.NoError(err)
				r.Len(list.Items, 2)
				r.ElementsMatch([]string{"unexpired secret", "some other unrelated secret"}, []string{list.Items[0].Name, list.Items[1].Name})
			})
		})

		when("there are valid, expired authcode secrets which contain upstream refresh tokens", func() {
			it.Before(func() {
				activeOIDCAuthcodeSession := &authorizationcode.Session{
					Version: currentSessionStorageVersion,
					Active:  true,
					Request: &fosite.Request{
						ID:     "request-id-1",
						Client: &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamRefreshToken: "fake-upstream-refresh-token",
								},
							},
						},
					},
				}
				activeOIDCAuthcodeSessionJSON, err := json.Marshal(activeOIDCAuthcodeSession)
				r.NoError(err)
				activeOIDCAuthcodeSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "activeOIDCAuthcodeSession",
						Namespace:       installedInNamespace,
						UID:             "uid-123",
						ResourceVersion: "rv-123",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": authorizationcode.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    activeOIDCAuthcodeSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + authorizationcode.TypeLabelValue,
				}
				_, err = authorizationcode.ReadFromSecret(activeOIDCAuthcodeSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid authcode secret")
				r.NoError(kubeInformerClient.Tracker().Add(activeOIDCAuthcodeSessionSecret))
				r.NoError(kubeClient.Tracker().Add(activeOIDCAuthcodeSessionSecret))

				inactiveOIDCAuthcodeSession := &authorizationcode.Session{
					Version: currentSessionStorageVersion,
					Active:  false,
					Request: &fosite.Request{
						ID:     "request-id-2",
						Client: &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamRefreshToken: "other-fake-upstream-refresh-token",
								},
							},
						},
					},
				}
				inactiveOIDCAuthcodeSessionJSON, err := json.Marshal(inactiveOIDCAuthcodeSession)
				r.NoError(err)
				inactiveOIDCAuthcodeSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "inactiveOIDCAuthcodeSession",
						Namespace:       installedInNamespace,
						UID:             "uid-456",
						ResourceVersion: "rv-456",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": authorizationcode.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    inactiveOIDCAuthcodeSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + authorizationcode.TypeLabelValue,
				}
				_, err = authorizationcode.ReadFromSecret(inactiveOIDCAuthcodeSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid authcode secret")
				r.NoError(kubeInformerClient.Tracker().Add(inactiveOIDCAuthcodeSessionSecret))
				r.NoError(kubeClient.Tracker().Add(inactiveOIDCAuthcodeSessionSecret))
			})

			it("should revoke upstream tokens only from the active authcode secrets and delete them all", func() {
				happyOIDCUpstream := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("upstream-oidc-provider-name").
					WithResourceUID("upstream-oidc-provider-uid").
					WithRevokeTokenError(nil)
				idpListerBuilder := testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream.Build())

				startInformersAndController(idpListerBuilder.BuildDynamicUpstreamIDPProvider())
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				// The upstream refresh token is only revoked for the active authcode session.
				idpListerBuilder.RequireExactlyOneCallToRevokeToken(t,
					"upstream-oidc-provider-name",
					&oidctestutil.RevokeTokenArgs{
						Ctx:       syncContext.Context,
						Token:     "fake-upstream-refresh-token",
						TokenType: upstreamprovider.RefreshTokenType,
					},
				)

				// Both authcode session secrets are deleted.
				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "activeOIDCAuthcodeSession", testutil.NewPreconditions("uid-123", "rv-123")),
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "inactiveOIDCAuthcodeSession", testutil.NewPreconditions("uid-456", "rv-456")),
					},
					kubeClient.Actions(),
				)

				wantAuditLogs = []testutil.WantedAuditLog{
					testutil.WantAuditLog("Upstream OIDC Token Revoked",
						map[string]any{
							"sessionID": "request-id-1",
							"type":      "refresh_token",
						},
					),
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-1",
							"storageType": "authcode",
						},
					),
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-2",
							"storageType": "authcode",
						},
					),
				}
			})
		})

		when("there are valid, expired authcode secrets which contain upstream access tokens", func() {
			it.Before(func() {
				activeOIDCAuthcodeSession := &authorizationcode.Session{
					Version: currentSessionStorageVersion,
					Active:  true,
					Request: &fosite.Request{
						ID:     "request-id-1",
						Client: &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamAccessToken: "fake-upstream-access-token",
								},
							},
						},
					},
				}
				activeOIDCAuthcodeSessionJSON, err := json.Marshal(activeOIDCAuthcodeSession)
				r.NoError(err)
				activeOIDCAuthcodeSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "activeOIDCAuthcodeSession",
						Namespace:       installedInNamespace,
						UID:             "uid-123",
						ResourceVersion: "rv-123",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": authorizationcode.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    activeOIDCAuthcodeSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + authorizationcode.TypeLabelValue,
				}
				_, err = authorizationcode.ReadFromSecret(activeOIDCAuthcodeSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid authcode secret")
				r.NoError(kubeInformerClient.Tracker().Add(activeOIDCAuthcodeSessionSecret))
				r.NoError(kubeClient.Tracker().Add(activeOIDCAuthcodeSessionSecret))

				inactiveOIDCAuthcodeSession := &authorizationcode.Session{
					Version: currentSessionStorageVersion,
					Active:  false,
					Request: &fosite.Request{
						ID:     "request-id-2",
						Client: &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamAccessToken: "other-fake-upstream-access-token",
								},
							},
						},
					},
				}
				inactiveOIDCAuthcodeSessionJSON, err := json.Marshal(inactiveOIDCAuthcodeSession)
				r.NoError(err)
				inactiveOIDCAuthcodeSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "inactiveOIDCAuthcodeSession",
						Namespace:       installedInNamespace,
						UID:             "uid-456",
						ResourceVersion: "rv-456",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": authorizationcode.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    inactiveOIDCAuthcodeSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + authorizationcode.TypeLabelValue,
				}
				_, err = authorizationcode.ReadFromSecret(inactiveOIDCAuthcodeSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid authcode secret")
				r.NoError(kubeInformerClient.Tracker().Add(inactiveOIDCAuthcodeSessionSecret))
				r.NoError(kubeClient.Tracker().Add(inactiveOIDCAuthcodeSessionSecret))
			})

			it("should revoke upstream tokens only from the active authcode secrets and delete them all", func() {
				happyOIDCUpstream := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("upstream-oidc-provider-name").
					WithResourceUID("upstream-oidc-provider-uid").
					WithRevokeTokenError(nil)
				idpListerBuilder := testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream.Build())

				startInformersAndController(idpListerBuilder.BuildDynamicUpstreamIDPProvider())
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				// The upstream refresh token is only revoked for the active authcode session.
				idpListerBuilder.RequireExactlyOneCallToRevokeToken(t,
					"upstream-oidc-provider-name",
					&oidctestutil.RevokeTokenArgs{
						Ctx:       syncContext.Context,
						Token:     "fake-upstream-access-token",
						TokenType: upstreamprovider.AccessTokenType,
					},
				)

				// Both authcode session secrets are deleted.
				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "activeOIDCAuthcodeSession", testutil.NewPreconditions("uid-123", "rv-123")),
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "inactiveOIDCAuthcodeSession", testutil.NewPreconditions("uid-456", "rv-456")),
					},
					kubeClient.Actions(),
				)

				wantAuditLogs = []testutil.WantedAuditLog{
					testutil.WantAuditLog("Upstream OIDC Token Revoked",
						map[string]any{
							"sessionID": "request-id-1",
							"type":      "access_token",
						},
					),
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-1",
							"storageType": "authcode",
						},
					),
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-2",
							"storageType": "authcode",
						},
					),
				}
			})
		})

		when("there is an invalid, expired authcode secret", func() {
			it.Before(func() {
				invalidOIDCAuthcodeSession := &authorizationcode.Session{
					Version: currentSessionStorageVersion,
					Active:  true,
					Request: &fosite.Request{
						ID:     "", // it is invalid for there to be a missing request ID
						Client: &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamRefreshToken: "fake-upstream-refresh-token",
								},
							},
						},
					},
				}
				invalidOIDCAuthcodeSessionJSON, err := json.Marshal(invalidOIDCAuthcodeSession)
				r.NoError(err)
				invalidOIDCAuthcodeSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "invalidOIDCAuthcodeSession",
						Namespace:       installedInNamespace,
						UID:             "uid-123",
						ResourceVersion: "rv-123",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": authorizationcode.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    invalidOIDCAuthcodeSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + authorizationcode.TypeLabelValue,
				}
				r.NoError(kubeInformerClient.Tracker().Add(invalidOIDCAuthcodeSessionSecret))
				r.NoError(kubeClient.Tracker().Add(invalidOIDCAuthcodeSessionSecret))
			})

			it("should remove the secret without revoking any upstream tokens", func() {
				happyOIDCUpstream := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("upstream-oidc-provider-name").
					WithResourceUID("upstream-oidc-provider-uid").
					WithRevokeTokenError(nil)
				idpListerBuilder := testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream.Build())

				startInformersAndController(idpListerBuilder.BuildDynamicUpstreamIDPProvider())
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				// Nothing to revoke since we couldn't read the invalid secret.
				idpListerBuilder.RequireExactlyZeroCallsToRevokeToken(t)

				// The invalid authcode session secrets is still deleted because it is expired.
				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "invalidOIDCAuthcodeSession", testutil.NewPreconditions("uid-123", "rv-123")),
					},
					kubeClient.Actions(),
				)
			})
		})

		when("there is a valid, expired authcode secret but its upstream name does not match any existing upstream", func() {
			it.Before(func() {
				wrongProviderNameOIDCAuthcodeSession := &authorizationcode.Session{
					Version: currentSessionStorageVersion,
					Active:  true,
					Request: &fosite.Request{
						ID:     "request-id-1",
						Client: &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name-will-not-match",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamRefreshToken: "fake-upstream-refresh-token",
								},
							},
						},
					},
				}
				wrongProviderNameOIDCAuthcodeSessionJSON, err := json.Marshal(wrongProviderNameOIDCAuthcodeSession)
				r.NoError(err)
				wrongProviderNameOIDCAuthcodeSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "wrongProviderNameOIDCAuthcodeSession",
						Namespace:       installedInNamespace,
						UID:             "uid-123",
						ResourceVersion: "rv-123",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": authorizationcode.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    wrongProviderNameOIDCAuthcodeSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + authorizationcode.TypeLabelValue,
				}
				_, err = authorizationcode.ReadFromSecret(wrongProviderNameOIDCAuthcodeSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid authcode secret")
				r.NoError(kubeInformerClient.Tracker().Add(wrongProviderNameOIDCAuthcodeSessionSecret))
				r.NoError(kubeClient.Tracker().Add(wrongProviderNameOIDCAuthcodeSessionSecret))
			})

			it("should remove the secret without revoking any upstream tokens", func() {
				happyOIDCUpstream := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("upstream-oidc-provider-name").
					WithResourceUID("upstream-oidc-provider-uid").
					WithRevokeTokenError(nil)
				idpListerBuilder := testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream.Build())

				startInformersAndController(idpListerBuilder.BuildDynamicUpstreamIDPProvider())
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				// Nothing to revoke since we couldn't find the upstream in the cache.
				idpListerBuilder.RequireExactlyZeroCallsToRevokeToken(t)

				// The authcode session secrets is still deleted because it is expired.
				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "wrongProviderNameOIDCAuthcodeSession", testutil.NewPreconditions("uid-123", "rv-123")),
					},
					kubeClient.Actions(),
				)

				wantAuditLogs = []testutil.WantedAuditLog{
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-1",
							"storageType": "authcode",
						},
					),
				}
			})
		})

		when("there is a valid, expired authcode secret but its upstream UID does not match any existing upstream", func() {
			it.Before(func() {
				wrongProviderNameOIDCAuthcodeSession := &authorizationcode.Session{
					Version: currentSessionStorageVersion,
					Active:  true,
					Request: &fosite.Request{
						ID:     "request-id-1",
						Client: &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid-will-not-match",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamRefreshToken: "fake-upstream-refresh-token",
								},
							},
						},
					},
				}
				wrongProviderNameOIDCAuthcodeSessionJSON, err := json.Marshal(wrongProviderNameOIDCAuthcodeSession)
				r.NoError(err)
				wrongProviderNameOIDCAuthcodeSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "wrongProviderNameOIDCAuthcodeSession",
						Namespace:       installedInNamespace,
						UID:             "uid-123",
						ResourceVersion: "rv-123",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": authorizationcode.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    wrongProviderNameOIDCAuthcodeSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + authorizationcode.TypeLabelValue,
				}
				_, err = authorizationcode.ReadFromSecret(wrongProviderNameOIDCAuthcodeSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid authcode secret")
				r.NoError(kubeInformerClient.Tracker().Add(wrongProviderNameOIDCAuthcodeSessionSecret))
				r.NoError(kubeClient.Tracker().Add(wrongProviderNameOIDCAuthcodeSessionSecret))
			})

			it("should remove the secret without revoking any upstream tokens", func() {
				happyOIDCUpstream := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("upstream-oidc-provider-name").
					WithResourceUID("upstream-oidc-provider-uid").
					WithRevokeTokenError(nil)
				idpListerBuilder := testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream.Build())

				startInformersAndController(idpListerBuilder.BuildDynamicUpstreamIDPProvider())
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				// Nothing to revoke since we couldn't find the upstream in the cache.
				idpListerBuilder.RequireExactlyZeroCallsToRevokeToken(t)

				// The authcode session secrets is still deleted because it is expired.
				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "wrongProviderNameOIDCAuthcodeSession", testutil.NewPreconditions("uid-123", "rv-123")),
					},
					kubeClient.Actions(),
				)

				wantAuditLogs = []testutil.WantedAuditLog{
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-1",
							"storageType": "authcode",
						},
					),
				}
			})
		})

		when("there is a valid, recently expired authcode secret but the upstream revocation fails", func() {
			it.Before(func() {
				activeOIDCAuthcodeSession := &authorizationcode.Session{
					Version: currentSessionStorageVersion,
					Active:  true,
					Request: &fosite.Request{
						ID:     "request-id-1",
						Client: &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamRefreshToken: "fake-upstream-refresh-token",
								},
							},
						},
					},
				}
				activeOIDCAuthcodeSessionJSON, err := json.Marshal(activeOIDCAuthcodeSession)
				r.NoError(err)
				activeOIDCAuthcodeSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "activeOIDCAuthcodeSession",
						Namespace:       installedInNamespace,
						UID:             "uid-123",
						ResourceVersion: "rv-123",
						Annotations: map[string]string{
							// expired almost 4 hours ago, but not quite 4 hours
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add((-time.Hour * 4) + time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": authorizationcode.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    activeOIDCAuthcodeSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + authorizationcode.TypeLabelValue,
				}
				_, err = authorizationcode.ReadFromSecret(activeOIDCAuthcodeSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid authcode secret")
				r.NoError(kubeInformerClient.Tracker().Add(activeOIDCAuthcodeSessionSecret))
				r.NoError(kubeClient.Tracker().Add(activeOIDCAuthcodeSessionSecret))
			})

			it("keeps the secret for a while longer so the revocation can be retried on a future sync for retryable errors", func() {
				happyOIDCUpstream := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("upstream-oidc-provider-name").
					WithResourceUID("upstream-oidc-provider-uid").
					// make the upstream revocation fail in a retryable way
					WithRevokeTokenError(dynamicupstreamprovider.NewRetryableRevocationError(errors.New("some retryable upstream revocation error")))
				idpListerBuilder := testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream.Build())

				startInformersAndController(idpListerBuilder.BuildDynamicUpstreamIDPProvider())
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				// Tried to revoke it, although this revocation will fail.
				idpListerBuilder.RequireExactlyOneCallToRevokeToken(t,
					"upstream-oidc-provider-name",
					&oidctestutil.RevokeTokenArgs{
						Ctx:       syncContext.Context,
						Token:     "fake-upstream-refresh-token",
						TokenType: upstreamprovider.RefreshTokenType,
					},
				)

				// The authcode session secrets is not deleted.
				r.Empty(kubeClient.Actions())
			})

			it("deletes the secret for non-retryable errors", func() {
				happyOIDCUpstream := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("upstream-oidc-provider-name").
					WithResourceUID("upstream-oidc-provider-uid").
					// make the upstream revocation fail in a non-retryable way
					WithRevokeTokenError(errors.New("some upstream revocation error not worth retrying"))
				idpListerBuilder := testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream.Build())

				startInformersAndController(idpListerBuilder.BuildDynamicUpstreamIDPProvider())
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				// Tried to revoke it, although this revocation will fail.
				idpListerBuilder.RequireExactlyOneCallToRevokeToken(t,
					"upstream-oidc-provider-name",
					&oidctestutil.RevokeTokenArgs{
						Ctx:       syncContext.Context,
						Token:     "fake-upstream-refresh-token",
						TokenType: upstreamprovider.RefreshTokenType,
					},
				)

				// The authcode session secrets is still deleted because it is expired and the revocation error is not retryable.
				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "activeOIDCAuthcodeSession", testutil.NewPreconditions("uid-123", "rv-123")),
					},
					kubeClient.Actions(),
				)

				wantAuditLogs = []testutil.WantedAuditLog{
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-1",
							"storageType": "authcode",
						},
					),
				}
			})
		})

		when("there is a valid, long-since expired authcode secret but the upstream revocation fails", func() {
			it.Before(func() {
				activeOIDCAuthcodeSession := &authorizationcode.Session{
					Version: currentSessionStorageVersion,
					Active:  true,
					Request: &fosite.Request{
						ID:     "request-id-1",
						Client: &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamRefreshToken: "fake-upstream-refresh-token",
								},
							},
						},
					},
				}
				activeOIDCAuthcodeSessionJSON, err := json.Marshal(activeOIDCAuthcodeSession)
				r.NoError(err)
				activeOIDCAuthcodeSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "activeOIDCAuthcodeSession",
						Namespace:       installedInNamespace,
						UID:             "uid-123",
						ResourceVersion: "rv-123",
						Annotations: map[string]string{
							// expired just over 4 hours ago
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add((-time.Hour * 4) - time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": authorizationcode.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    activeOIDCAuthcodeSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + authorizationcode.TypeLabelValue,
				}
				_, err = authorizationcode.ReadFromSecret(activeOIDCAuthcodeSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid authcode secret")
				r.NoError(kubeInformerClient.Tracker().Add(activeOIDCAuthcodeSessionSecret))
				r.NoError(kubeClient.Tracker().Add(activeOIDCAuthcodeSessionSecret))
			})

			it("deletes the secret because it has probably been retrying revocation for hours without success", func() {
				happyOIDCUpstream := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("upstream-oidc-provider-name").
					WithResourceUID("upstream-oidc-provider-uid").
					WithRevokeTokenError(errors.New("some upstream revocation error")) // the upstream revocation will fail
				idpListerBuilder := testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream.Build())

				startInformersAndController(idpListerBuilder.BuildDynamicUpstreamIDPProvider())
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				// Tried to revoke it, although this revocation will fail.
				idpListerBuilder.RequireExactlyOneCallToRevokeToken(t,
					"upstream-oidc-provider-name",
					&oidctestutil.RevokeTokenArgs{
						Ctx:       syncContext.Context,
						Token:     "fake-upstream-refresh-token",
						TokenType: upstreamprovider.RefreshTokenType,
					},
				)

				// The authcode session secrets is deleted.
				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "activeOIDCAuthcodeSession", testutil.NewPreconditions("uid-123", "rv-123")),
					},
					kubeClient.Actions(),
				)

				wantAuditLogs = []testutil.WantedAuditLog{
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-1",
							"storageType": "authcode",
						},
					),
				}
			})
		})

		when("there are valid, expired access token secrets which contain upstream refresh tokens", func() {
			it.Before(func() {
				offlineAccessGrantedOIDCAccessTokenSession := &accesstoken.Session{
					Version: currentSessionStorageVersion,
					Request: &fosite.Request{
						GrantedScope: fosite.Arguments{"scope1", "scope2", "offline_access"},
						ID:           "request-id-1",
						Client:       &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamRefreshToken: "offline-access-granted-fake-upstream-refresh-token",
								},
							},
						},
					},
				}
				offlineAccessGrantedOIDCAccessTokenSessionJSON, err := json.Marshal(offlineAccessGrantedOIDCAccessTokenSession)
				r.NoError(err)
				offlineAccessGrantedOIDCAccessTokenSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "offlineAccessGrantedOIDCAccessTokenSession",
						Namespace:       installedInNamespace,
						UID:             "uid-123",
						ResourceVersion: "rv-123",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": accesstoken.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    offlineAccessGrantedOIDCAccessTokenSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + accesstoken.TypeLabelValue,
				}
				_, err = accesstoken.ReadFromSecret(offlineAccessGrantedOIDCAccessTokenSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid accesstoken secret")
				r.NoError(kubeInformerClient.Tracker().Add(offlineAccessGrantedOIDCAccessTokenSessionSecret))
				r.NoError(kubeClient.Tracker().Add(offlineAccessGrantedOIDCAccessTokenSessionSecret))

				offlineAccessNotGrantedOIDCAccessTokenSession := &accesstoken.Session{
					Version: currentSessionStorageVersion,
					Request: &fosite.Request{
						GrantedScope: fosite.Arguments{"scope1", "scope2"},
						ID:           "request-id-2",
						Client:       &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamRefreshToken: "fake-upstream-refresh-token",
								},
							},
						},
					},
				}
				offlineAccessNotGrantedOIDCAccessTokenSessionJSON, err := json.Marshal(offlineAccessNotGrantedOIDCAccessTokenSession)
				r.NoError(err)
				offlineAccessNotGrantedOIDCAccessTokenSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "offlineAccessNotGrantedOIDCAccessTokenSession",
						Namespace:       installedInNamespace,
						UID:             "uid-456",
						ResourceVersion: "rv-456",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": accesstoken.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    offlineAccessNotGrantedOIDCAccessTokenSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + accesstoken.TypeLabelValue,
				}
				_, err = accesstoken.ReadFromSecret(offlineAccessNotGrantedOIDCAccessTokenSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid accesstoken secret")
				r.NoError(kubeInformerClient.Tracker().Add(offlineAccessNotGrantedOIDCAccessTokenSessionSecret))
				r.NoError(kubeClient.Tracker().Add(offlineAccessNotGrantedOIDCAccessTokenSessionSecret))
			})

			it("should revoke upstream tokens only from the active authcode secrets and delete them all", func() {
				happyOIDCUpstream := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("upstream-oidc-provider-name").
					WithResourceUID("upstream-oidc-provider-uid").
					WithRevokeTokenError(nil)
				idpListerBuilder := testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream.Build())

				startInformersAndController(idpListerBuilder.BuildDynamicUpstreamIDPProvider())
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				// The upstream refresh token is only revoked for the downstream session which had offline_access granted.
				idpListerBuilder.RequireExactlyOneCallToRevokeToken(t,
					"upstream-oidc-provider-name",
					&oidctestutil.RevokeTokenArgs{
						Ctx:       syncContext.Context,
						Token:     "fake-upstream-refresh-token",
						TokenType: upstreamprovider.RefreshTokenType,
					},
				)

				// Both session secrets are deleted.
				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "offlineAccessGrantedOIDCAccessTokenSession", testutil.NewPreconditions("uid-123", "rv-123")),
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "offlineAccessNotGrantedOIDCAccessTokenSession", testutil.NewPreconditions("uid-456", "rv-456")),
					},
					kubeClient.Actions(),
				)

				wantAuditLogs = []testutil.WantedAuditLog{
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-1",
							"storageType": "access-token",
						},
					),
					testutil.WantAuditLog("Upstream OIDC Token Revoked",
						map[string]any{
							"sessionID": "request-id-2",
							"type":      "refresh_token",
						},
					),
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-2",
							"storageType": "access-token",
						},
					),
				}
			})
		})

		when("there are valid, expired access token secrets which contain upstream access tokens", func() {
			it.Before(func() {
				offlineAccessGrantedOIDCAccessTokenSession := &accesstoken.Session{
					Version: currentSessionStorageVersion,
					Request: &fosite.Request{
						GrantedScope: fosite.Arguments{"scope1", "scope2", "offline_access"},
						ID:           "request-id-1",
						Client:       &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamAccessToken: "offline-access-granted-fake-upstream-access-token",
								},
							},
						},
					},
				}
				offlineAccessGrantedOIDCAccessTokenSessionJSON, err := json.Marshal(offlineAccessGrantedOIDCAccessTokenSession)
				r.NoError(err)
				offlineAccessGrantedOIDCAccessTokenSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "offlineAccessGrantedOIDCAccessTokenSession",
						Namespace:       installedInNamespace,
						UID:             "uid-123",
						ResourceVersion: "rv-123",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": accesstoken.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    offlineAccessGrantedOIDCAccessTokenSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + accesstoken.TypeLabelValue,
				}
				_, err = accesstoken.ReadFromSecret(offlineAccessGrantedOIDCAccessTokenSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid accesstoken secret")
				r.NoError(kubeInformerClient.Tracker().Add(offlineAccessGrantedOIDCAccessTokenSessionSecret))
				r.NoError(kubeClient.Tracker().Add(offlineAccessGrantedOIDCAccessTokenSessionSecret))

				offlineAccessNotGrantedOIDCAccessTokenSession := &accesstoken.Session{
					Version: currentSessionStorageVersion,
					Request: &fosite.Request{
						GrantedScope: fosite.Arguments{"scope1", "scope2"},
						ID:           "request-id-2",
						Client:       &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamAccessToken: "fake-upstream-access-token",
								},
							},
						},
					},
				}
				offlineAccessNotGrantedOIDCAccessTokenSessionJSON, err := json.Marshal(offlineAccessNotGrantedOIDCAccessTokenSession)
				r.NoError(err)
				offlineAccessNotGrantedOIDCAccessTokenSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "offlineAccessNotGrantedOIDCAccessTokenSession",
						Namespace:       installedInNamespace,
						UID:             "uid-456",
						ResourceVersion: "rv-456",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": accesstoken.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    offlineAccessNotGrantedOIDCAccessTokenSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + accesstoken.TypeLabelValue,
				}
				_, err = accesstoken.ReadFromSecret(offlineAccessNotGrantedOIDCAccessTokenSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid accesstoken secret")
				r.NoError(kubeInformerClient.Tracker().Add(offlineAccessNotGrantedOIDCAccessTokenSessionSecret))
				r.NoError(kubeClient.Tracker().Add(offlineAccessNotGrantedOIDCAccessTokenSessionSecret))
			})

			it("should revoke upstream tokens only from the active authcode secrets and delete them all", func() {
				happyOIDCUpstream := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("upstream-oidc-provider-name").
					WithResourceUID("upstream-oidc-provider-uid").
					WithRevokeTokenError(nil)
				idpListerBuilder := testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream.Build())

				startInformersAndController(idpListerBuilder.BuildDynamicUpstreamIDPProvider())
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				// The upstream refresh token is only revoked for the downstream session which had offline_access granted.
				idpListerBuilder.RequireExactlyOneCallToRevokeToken(t,
					"upstream-oidc-provider-name",
					&oidctestutil.RevokeTokenArgs{
						Ctx:       syncContext.Context,
						Token:     "fake-upstream-access-token",
						TokenType: upstreamprovider.AccessTokenType,
					},
				)

				// Both session secrets are deleted.
				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "offlineAccessGrantedOIDCAccessTokenSession", testutil.NewPreconditions("uid-123", "rv-123")),
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "offlineAccessNotGrantedOIDCAccessTokenSession", testutil.NewPreconditions("uid-456", "rv-456")),
					},
					kubeClient.Actions(),
				)

				wantAuditLogs = []testutil.WantedAuditLog{
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-1",
							"storageType": "access-token",
						},
					),
					testutil.WantAuditLog("Upstream OIDC Token Revoked",
						map[string]any{
							"sessionID": "request-id-2",
							"type":      "access_token",
						},
					),
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-2",
							"storageType": "access-token",
						},
					),
				}
			})
		})

		when("there are valid, expired refresh secrets which contain upstream refresh tokens", func() {
			it.Before(func() {
				oidcRefreshSession := &refreshtoken.Session{
					Version: currentSessionStorageVersion,
					Request: &fosite.Request{
						ID:     "request-id-1",
						Client: &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamRefreshToken: "fake-upstream-refresh-token",
								},
							},
						},
					},
				}
				oidcRefreshSessionJSON, err := json.Marshal(oidcRefreshSession)
				r.NoError(err)
				oidcRefreshSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "oidcRefreshSession",
						Namespace:       installedInNamespace,
						UID:             "uid-123",
						ResourceVersion: "rv-123",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": refreshtoken.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    oidcRefreshSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + refreshtoken.TypeLabelValue,
				}
				_, err = refreshtoken.ReadFromSecret(oidcRefreshSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid refresh token secret")
				r.NoError(kubeInformerClient.Tracker().Add(oidcRefreshSessionSecret))
				r.NoError(kubeClient.Tracker().Add(oidcRefreshSessionSecret))
			})

			it("should revoke upstream tokens from the secrets and delete them all", func() {
				happyOIDCUpstream := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("upstream-oidc-provider-name").
					WithResourceUID("upstream-oidc-provider-uid").
					WithRevokeTokenError(nil)
				idpListerBuilder := testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream.Build())

				startInformersAndController(idpListerBuilder.BuildDynamicUpstreamIDPProvider())
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				// The upstream refresh token is revoked.
				idpListerBuilder.RequireExactlyOneCallToRevokeToken(t,
					"upstream-oidc-provider-name",
					&oidctestutil.RevokeTokenArgs{
						Ctx:       syncContext.Context,
						Token:     "fake-upstream-refresh-token",
						TokenType: upstreamprovider.RefreshTokenType,
					},
				)

				// The secret is deleted.
				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "oidcRefreshSession", testutil.NewPreconditions("uid-123", "rv-123")),
					},
					kubeClient.Actions(),
				)

				wantAuditLogs = []testutil.WantedAuditLog{
					testutil.WantAuditLog("Upstream OIDC Token Revoked",
						map[string]any{
							"sessionID": "request-id-1",
							"type":      "refresh_token",
						},
					),
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-1",
							"storageType": "refresh-token",
						},
					),
				}
			})
		})

		when("there are valid, expired refresh secrets which contain upstream access tokens", func() {
			it.Before(func() {
				oidcRefreshSession := &refreshtoken.Session{
					Version: currentSessionStorageVersion,
					Request: &fosite.Request{
						ID:     "request-id-1",
						Client: &clientregistry.Client{},
						Session: &psession.PinnipedSession{
							Custom: &psession.CustomSessionData{
								Username:     "should be ignored by garbage collector",
								ProviderUID:  "upstream-oidc-provider-uid",
								ProviderName: "upstream-oidc-provider-name",
								ProviderType: psession.ProviderTypeOIDC,
								OIDC: &psession.OIDCSessionData{
									UpstreamAccessToken: "fake-upstream-access-token",
								},
							},
						},
					},
				}
				oidcRefreshSessionJSON, err := json.Marshal(oidcRefreshSession)
				r.NoError(err)
				oidcRefreshSessionSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "oidcRefreshSession",
						Namespace:       installedInNamespace,
						UID:             "uid-123",
						ResourceVersion: "rv-123",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
						Labels: map[string]string{
							"storage.pinniped.dev/type": refreshtoken.TypeLabelValue,
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    oidcRefreshSessionJSON,
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/" + refreshtoken.TypeLabelValue,
				}
				_, err = refreshtoken.ReadFromSecret(oidcRefreshSessionSecret)
				r.NoError(err, "the test author accidentally formed an invalid refresh token secret")
				r.NoError(kubeInformerClient.Tracker().Add(oidcRefreshSessionSecret))
				r.NoError(kubeClient.Tracker().Add(oidcRefreshSessionSecret))
			})

			it("should revoke upstream tokens from the secrets and delete them all", func() {
				happyOIDCUpstream := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
					WithName("upstream-oidc-provider-name").
					WithResourceUID("upstream-oidc-provider-uid").
					WithRevokeTokenError(nil)
				idpListerBuilder := testidplister.NewUpstreamIDPListerBuilder().WithOIDC(happyOIDCUpstream.Build())

				startInformersAndController(idpListerBuilder.BuildDynamicUpstreamIDPProvider())
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				// The upstream refresh token is revoked.
				idpListerBuilder.RequireExactlyOneCallToRevokeToken(t,
					"upstream-oidc-provider-name",
					&oidctestutil.RevokeTokenArgs{
						Ctx:       syncContext.Context,
						Token:     "fake-upstream-access-token",
						TokenType: upstreamprovider.AccessTokenType,
					},
				)

				// The secret is deleted.
				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "oidcRefreshSession", testutil.NewPreconditions("uid-123", "rv-123")),
					},
					kubeClient.Actions(),
				)

				wantAuditLogs = []testutil.WantedAuditLog{
					testutil.WantAuditLog("Upstream OIDC Token Revoked",
						map[string]any{
							"sessionID": "request-id-1",
							"type":      "access_token",
						},
					),
					testutil.WantAuditLog("Session Garbage Collected",
						map[string]any{
							"sessionID":   "request-id-1",
							"storageType": "refresh-token",
						},
					),
				}
			})
		})

		when("very little time has passed since the previous sync call", func() {
			it.Before(func() {
				// Add a secret that will expire in 20 seconds.
				expiredSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "expired secret",
						Namespace:       installedInNamespace,
						UID:             "uid-747",
						ResourceVersion: "rv-609",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(20 * time.Second).Format(time.RFC3339),
						},
					},
				}
				r.NoError(kubeInformerClient.Tracker().Add(expiredSecret))
				r.NoError(kubeClient.Tracker().Add(expiredSecret))
			})

			it("should do nothing to avoid being super chatty since it is called for every change to any Secret, until more time has passed", func() {
				startInformersAndController(nil)
				require.Empty(t, kubeClient.Actions())

				// Run sync once with the current time set to frozenTime.
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				require.Empty(t, kubeClient.Actions())
				r.False(syncContext.Queue.(*testQueue).called)

				// Run sync again when not enough time has passed since the most recent run, so no delete
				// operations should happen even though there is an expired secret now.
				fakeClock.Step(29 * time.Second)
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				require.Empty(t, kubeClient.Actions())
				r.True(syncContext.Queue.(*testQueue).called)
				r.Equal(controllerlib.Key{Namespace: "foo", Name: "bar"}, syncContext.Queue.(*testQueue).key) // assert key is passed through
				r.Equal(time.Second, syncContext.Queue.(*testQueue).duration)                                 // assert that we get the exact requeue time

				syncContext.Queue = &testQueue{t: t} // reset the queue for the next sync

				// Step to the exact threshold and run Sync again. Now we are past the rate limiting period.
				fakeClock.Step(time.Second)
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				r.False(syncContext.Queue.(*testQueue).called)

				// It should have deleted the expired secret.
				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "expired secret", testutil.NewPreconditions("uid-747", "rv-609")),
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
						Name:            "expired secret",
						Namespace:       installedInNamespace,
						UID:             "uid-748",
						ResourceVersion: "rv-608",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
					},
				}
				r.NoError(kubeInformerClient.Tracker().Add(expiredSecret))
				r.NoError(kubeClient.Tracker().Add(expiredSecret))
			})

			it("does not delete that secret", func() {
				startInformersAndController(nil)
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "expired secret", testutil.NewPreconditions("uid-748", "rv-608")),
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
						Name:            "erroring secret",
						Namespace:       installedInNamespace,
						UID:             "uid-111",
						ResourceVersion: "rv-222",
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
						Name:            "expired secret",
						Namespace:       installedInNamespace,
						UID:             "uid-333",
						ResourceVersion: "rv-444",
						Annotations: map[string]string{
							"storage.pinniped.dev/garbage-collect-after": frozenNow.Add(-time.Second).Format(time.RFC3339),
						},
					},
				}
				r.NoError(kubeInformerClient.Tracker().Add(expiredSecret))
				r.NoError(kubeClient.Tracker().Add(expiredSecret))
			})

			it("ignores the error and continues on to delete the next expired Secret", func() {
				startInformersAndController(nil)
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				r.ElementsMatch(
					[]kubetesting.Action{
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "erroring secret", testutil.NewPreconditions("uid-111", "rv-222")),
						kubetesting.NewDeleteActionWithOptions(secretsGVR, installedInNamespace, "expired secret", testutil.NewPreconditions("uid-333", "rv-444")),
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

type testQueue struct {
	t *testing.T

	called   bool
	key      controllerlib.Key
	duration time.Duration

	controllerlib.Queue // panic if any other methods called
}

func (q *testQueue) AddAfter(key controllerlib.Key, duration time.Duration) {
	q.t.Helper()

	require.False(q.t, q.called, "AddAfter should only be called once")

	q.called = true
	q.key = key
	q.duration = duration
}
