// Copyright 2022-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcclientwatcher

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func TestOIDCClientWatcherControllerFilterSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		secret     metav1.Object
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name: "a secret of the right type",
			secret: &corev1.Secret{
				Type:       "storage.pinniped.dev/oidc-client-secret",
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "a secret of the wrong type",
			secret: &corev1.Secret{
				Type:       "secrets.pinniped.dev/some-other-type",
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
		},
		{
			name: "resource of wrong data type",
			secret: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
		},
	}
	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			secretInformer := kubeinformers.NewSharedInformerFactory(
				kubernetesfake.NewSimpleClientset(),
				0,
			).Core().V1().Secrets()
			oidcClientsInformer := pinnipedinformers.NewSharedInformerFactory(
				pinnipedfake.NewSimpleClientset(),
				0,
			).Config().V1alpha1().OIDCClients()
			withInformer := testutil.NewObservableWithInformerOption()
			_ = NewOIDCClientWatcherController(
				nil, // pinnipedClient, not needed
				secretInformer,
				oidcClientsInformer,
				withInformer.WithInformer,
			)

			unrelated := corev1.Secret{}
			filter := withInformer.GetFilterForInformer(secretInformer)
			require.Equal(t, tt.wantAdd, filter.Add(tt.secret))
			require.Equal(t, tt.wantUpdate, filter.Update(&unrelated, tt.secret))
			require.Equal(t, tt.wantUpdate, filter.Update(tt.secret, &unrelated))
			require.Equal(t, tt.wantDelete, filter.Delete(tt.secret))
		})
	}
}

func TestOIDCClientWatcherControllerFilterOIDCClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		oidcClient configv1alpha1.OIDCClient
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name: "name has client.oauth.pinniped.dev- prefix",
			oidcClient: configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: "client.oauth.pinniped.dev-foo"},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "name does not have client.oauth.pinniped.dev- prefix",
			oidcClient: configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: "something.oauth.pinniped.dev-foo"},
			},
			wantAdd:    false,
			wantUpdate: false,
			wantDelete: false,
		},
		{
			name: "other names without any particular pinniped.dev prefixes",
			oidcClient: configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: "something"},
			},
			wantAdd:    false,
			wantUpdate: false,
			wantDelete: false,
		},
	}
	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			secretInformer := kubeinformers.NewSharedInformerFactory(
				kubernetesfake.NewSimpleClientset(),
				0,
			).Core().V1().Secrets()
			oidcClientsInformer := pinnipedinformers.NewSharedInformerFactory(
				pinnipedfake.NewSimpleClientset(),
				0,
			).Config().V1alpha1().OIDCClients()
			withInformer := testutil.NewObservableWithInformerOption()
			_ = NewOIDCClientWatcherController(
				nil, // pinnipedClient, not needed
				secretInformer,
				oidcClientsInformer,
				withInformer.WithInformer,
			)

			unrelated := configv1alpha1.OIDCClient{}
			filter := withInformer.GetFilterForInformer(oidcClientsInformer)
			require.Equal(t, tt.wantAdd, filter.Add(&tt.oidcClient))
			require.Equal(t, tt.wantUpdate, filter.Update(&unrelated, &tt.oidcClient))
			require.Equal(t, tt.wantUpdate, filter.Update(&tt.oidcClient, &unrelated))
			require.Equal(t, tt.wantDelete, filter.Delete(&tt.oidcClient))
		})
	}
}

func TestOIDCClientWatcherControllerSync(t *testing.T) {
	t.Parallel()

	const (
		testName      = "client.oauth.pinniped.dev-test-name"
		testNamespace = "test-namespace"
		testUID       = "test-uid-123"
	)

	now := metav1.NewTime(time.Now().UTC())
	earlier := metav1.NewTime(now.Add(-1 * time.Hour).UTC())

	happyAllowedGrantTypesCondition := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "AllowedGrantTypesValid",
			Status:             "True",
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            `"allowedGrantTypes" is valid`,
			ObservedGeneration: observedGeneration,
		}
	}

	sadAllowedGrantTypesCondition := func(time metav1.Time, observedGeneration int64, message string) metav1.Condition {
		return metav1.Condition{
			Type:               "AllowedGrantTypesValid",
			Status:             "False",
			LastTransitionTime: time,
			Reason:             "MissingRequiredValue",
			Message:            message,
			ObservedGeneration: observedGeneration,
		}
	}

	happyClientSecretsCondition := func(howMany int, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "ClientSecretExists",
			Status:             "True",
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            fmt.Sprintf(`%d client secret(s) found`, howMany),
			ObservedGeneration: observedGeneration,
		}
	}

	sadNoClientSecretsCondition := func(time metav1.Time, observedGeneration int64, message string) metav1.Condition {
		return metav1.Condition{
			Type:               "ClientSecretExists",
			Status:             "False",
			LastTransitionTime: time,
			Reason:             "NoClientSecretFound",
			Message:            message,
			ObservedGeneration: observedGeneration,
		}
	}

	sadInvalidClientSecretsCondition := func(time metav1.Time, observedGeneration int64, message string) metav1.Condition {
		return metav1.Condition{
			Type:               "ClientSecretExists",
			Status:             "False",
			LastTransitionTime: time,
			Reason:             "InvalidClientSecretFound",
			Message:            message,
			ObservedGeneration: observedGeneration,
		}
	}

	happyAllowedScopesCondition := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "AllowedScopesValid",
			Status:             "True",
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            `"allowedScopes" is valid`,
			ObservedGeneration: observedGeneration,
		}
	}

	sadAllowedScopesCondition := func(time metav1.Time, observedGeneration int64, message string) metav1.Condition {
		return metav1.Condition{
			Type:               "AllowedScopesValid",
			Status:             "False",
			LastTransitionTime: time,
			Reason:             "MissingRequiredValue",
			Message:            message,
			ObservedGeneration: observedGeneration,
		}
	}

	tests := []struct {
		name                     string
		inputObjects             []runtime.Object
		inputSecrets             []runtime.Object
		wantErr                  string
		wantResultingOIDCClients []configv1alpha1.OIDCClient
		wantAPIActions           int
	}{
		{
			name:           "no OIDCClients",
			wantAPIActions: 0, // no updates
		},
		{
			name: "OIDCClient with wrong prefix is ignored",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "wrong-prefix-name", Generation: 1234, UID: testUID},
			}},
			wantAPIActions: 0, // no updates
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "wrong-prefix-name", Generation: 1234, UID: testUID},
			}},
		},
		{
			name: "successfully validate minimal OIDCClient and one client secret stored (while ignoring client with wrong prefix)",
			inputObjects: []runtime.Object{
				&configv1alpha1.OIDCClient{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "wrong-prefix-name", Generation: 1234, UID: testUID},
				},
				&configv1alpha1.OIDCClient{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
					Spec: configv1alpha1.OIDCClientSpec{
						AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code"},
						AllowedScopes:     []configv1alpha1.Scope{"openid"},
					},
				},
			},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "wrong-prefix-name", Generation: 1234, UID: testUID},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
					Status: configv1alpha1.OIDCClientStatus{
						Phase: "Ready",
						Conditions: []metav1.Condition{
							happyAllowedGrantTypesCondition(now, 1234),
							happyAllowedScopesCondition(now, 1234),
							happyClientSecretsCondition(1, now, 1234),
						},
						TotalClientSecrets: 1,
					},
				},
			},
		},
		{
			name: "successfully validate minimal OIDCClient and two client secrets stored",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code"},
					AllowedScopes:     []configv1alpha1.Scope{"openid"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost, testutil.HashedPassword2AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						happyAllowedScopesCondition(now, 1234),
						happyClientSecretsCondition(2, now, 1234),
					},
					TotalClientSecrets: 2,
				},
			}},
		},
		{
			name: "an already validated OIDCClient does not have its conditions updated when everything is still valid",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code"},
					AllowedScopes:     []configv1alpha1.Scope{"openid"},
				},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(earlier, 1234),
						happyAllowedScopesCondition(earlier, 1234),
						happyClientSecretsCondition(1, earlier, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 0, // no updates
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(earlier, 1234),
						happyAllowedScopesCondition(earlier, 1234),
						happyClientSecretsCondition(1, earlier, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "missing required minimum settings and missing client secret storage",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec:       configv1alpha1.OIDCClientSpec{},
			}},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						sadAllowedGrantTypesCondition(now, 1234, `"authorization_code" must always be included in "allowedGrantTypes"`),
						sadAllowedScopesCondition(now, 1234, `"openid" must always be included in "allowedScopes"`),
						sadNoClientSecretsCondition(now, 1234, "no client secret found (no Secret storage found)"),
					},
				},
			}},
		},
		{
			name: "client secret storage exists but cannot be read",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code"},
					AllowedScopes:     []configv1alpha1.Scope{"openid"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUIDWithWrongVersion(t, testNamespace, testUID)},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						happyAllowedScopesCondition(now, 1234),
						sadNoClientSecretsCondition(now, 1234, "error reading client secret storage: OIDC client secret storage data has wrong version: OIDC client secret storage has version wrong-version instead of 1"),
					},
				},
			}},
		},
		{
			name: "client secret storage exists but does not contain any client secrets",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code"},
					AllowedScopes:     []configv1alpha1.Scope{"openid"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						happyAllowedScopesCondition(now, 1234),
						sadNoClientSecretsCondition(now, 1234, "no client secret found (empty list in storage)"),
					},
					TotalClientSecrets: 0,
				},
			}},
		},
		{
			name: "client secret storage exists but some of the client secrets are invalid bcrypt hashes",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code"},
					AllowedScopes:     []configv1alpha1.Scope{"openid"},
				},
			}},
			inputSecrets: []runtime.Object{
				testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID,
					[]string{testutil.HashedPassword1AtSupervisorMinCost, testutil.HashedPassword1JustBelowSupervisorMinCost, testutil.HashedPassword1InvalidFormat}),
			},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						happyAllowedScopesCondition(now, 1234),
						sadInvalidClientSecretsCondition(now, 1234,
							"3 stored client secrets found, but some were invalid, so none will be used: "+
								"hashed client secret at index 1: bcrypt cost 11 is below the required minimum of 12; "+
								"hashed client secret at index 2: crypto/bcrypt: hashedSecret too short to be a bcrypted password"),
					},
					TotalClientSecrets: 0,
				},
			}},
		},
		{
			name: "can operate on multiple at a time, e.g. one is valid one another is missing required minimum settings",
			inputObjects: []runtime.Object{
				&configv1alpha1.OIDCClient{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "client.oauth.pinniped.dev-test1", Generation: 1234, UID: "uid1"},
					Spec: configv1alpha1.OIDCClientSpec{
						AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code"},
						AllowedScopes:     []configv1alpha1.Scope{"openid"},
					},
				},
				&configv1alpha1.OIDCClient{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "client.oauth.pinniped.dev-test2", Generation: 4567, UID: "uid2"},
					Spec:       configv1alpha1.OIDCClientSpec{},
				},
			},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, "uid1", []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 2, // one update for each OIDCClient
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "client.oauth.pinniped.dev-test1", Generation: 1234, UID: "uid1"},
					Status: configv1alpha1.OIDCClientStatus{
						Phase: "Ready",
						Conditions: []metav1.Condition{
							happyAllowedGrantTypesCondition(now, 1234),
							happyAllowedScopesCondition(now, 1234),
							happyClientSecretsCondition(1, now, 1234),
						},
						TotalClientSecrets: 1,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "client.oauth.pinniped.dev-test2", Generation: 4567, UID: "uid2"},
					Status: configv1alpha1.OIDCClientStatus{
						Phase: "Error",
						Conditions: []metav1.Condition{
							sadAllowedGrantTypesCondition(now, 4567, `"authorization_code" must always be included in "allowedGrantTypes"`),
							sadAllowedScopesCondition(now, 4567, `"openid" must always be included in "allowedScopes"`),
							sadNoClientSecretsCondition(now, 4567, "no client secret found (no Secret storage found)"),
						},
						TotalClientSecrets: 0,
					},
				},
			},
		},
		{
			name: "a previously invalid OIDCClient has its spec changed to become valid so the conditions are updated",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 4567, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code"},
					AllowedScopes:     []configv1alpha1.Scope{"openid"},
				},
				// was invalid on previous run of controller which observed an old generation at an earlier time
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						sadAllowedGrantTypesCondition(earlier, 1234, `"authorization_code" must always be included in "allowedGrantTypes"`),
						sadAllowedScopesCondition(earlier, 1234, `"openid" must always be included in "allowedScopes"`),
						happyClientSecretsCondition(1, earlier, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 4567, UID: testUID},
				// status was updated to reflect the current generation at the current time
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 4567),
						happyAllowedScopesCondition(now, 4567),
						happyClientSecretsCondition(1, earlier, 4567), // was already validated earlier
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "refresh_token must be included in allowedGrantTypes when offline_access is included in allowedScopes",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code"},
					AllowedScopes:     []configv1alpha1.Scope{"openid", "offline_access"},
				},
			}},
			wantAPIActions: 1, // one update
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						sadAllowedGrantTypesCondition(now, 1234, `"refresh_token" must be included in "allowedGrantTypes" when "offline_access" is included in "allowedScopes"`),
						happyAllowedScopesCondition(now, 1234),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "multiple errors on allowedScopes and allowedGrantTypes",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"refresh_token"},
					AllowedScopes:     []configv1alpha1.Scope{"pinniped:request-audience"},
				},
			}},
			wantAPIActions: 1, // one update
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						sadAllowedGrantTypesCondition(now, 1234,
							`"authorization_code" must always be included in "allowedGrantTypes"; `+
								`"urn:ietf:params:oauth:grant-type:token-exchange" must be included in "allowedGrantTypes" when "pinniped:request-audience" is included in "allowedScopes"`),
						sadAllowedScopesCondition(now, 1234,
							`"openid" must always be included in "allowedScopes"; `+
								`"offline_access" must be included in "allowedScopes" when "refresh_token" is included in "allowedGrantTypes"; `+
								`"username" and "groups" must be included in "allowedScopes" when "pinniped:request-audience" is included in "allowedScopes"`),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "another combination of multiple errors on allowedScopes and allowedGrantTypes",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"urn:ietf:params:oauth:grant-type:token-exchange"},
					AllowedScopes:     []configv1alpha1.Scope{"offline_access"},
				},
			}},
			wantAPIActions: 1, // one update
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						sadAllowedGrantTypesCondition(now, 1234,
							`"authorization_code" must always be included in "allowedGrantTypes"; `+
								`"refresh_token" must be included in "allowedGrantTypes" when "offline_access" is included in "allowedScopes"`),
						sadAllowedScopesCondition(now, 1234,
							`"openid" must always be included in "allowedScopes"; `+
								`"pinniped:request-audience" must be included in "allowedScopes" when "urn:ietf:params:oauth:grant-type:token-exchange" is included in "allowedGrantTypes"`),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "urn:ietf:params:oauth:grant-type:token-exchange must be included in allowedGrantTypes when pinniped:request-audience is included in allowedScopes",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code"},
					AllowedScopes:     []configv1alpha1.Scope{"openid", "pinniped:request-audience", "username", "groups"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						sadAllowedGrantTypesCondition(now, 1234, `"urn:ietf:params:oauth:grant-type:token-exchange" must be included in "allowedGrantTypes" when "pinniped:request-audience" is included in "allowedScopes"`),
						happyAllowedScopesCondition(now, 1234),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "offline_access must be included in allowedScopes when refresh_token is included in allowedGrantTypes",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code", "refresh_token"},
					AllowedScopes:     []configv1alpha1.Scope{"openid"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						sadAllowedScopesCondition(now, 1234, `"offline_access" must be included in "allowedScopes" when "refresh_token" is included in "allowedGrantTypes"`),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "username and groups must also be included in allowedScopes when pinniped:request-audience is included in allowedScopes: both missing",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
					AllowedScopes:     []configv1alpha1.Scope{"openid", "pinniped:request-audience"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						sadAllowedScopesCondition(now, 1234, `"username" and "groups" must be included in "allowedScopes" when "pinniped:request-audience" is included in "allowedScopes"`),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "username and groups must also be included in allowedScopes when pinniped:request-audience is included in allowedScopes: username missing",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
					AllowedScopes:     []configv1alpha1.Scope{"openid", "pinniped:request-audience", "groups"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						sadAllowedScopesCondition(now, 1234, `"username" and "groups" must be included in "allowedScopes" when "pinniped:request-audience" is included in "allowedScopes"`),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "username and groups must also be included in allowedScopes when pinniped:request-audience is included in allowedScopes: groups missing",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
					AllowedScopes:     []configv1alpha1.Scope{"openid", "pinniped:request-audience", "username"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						sadAllowedScopesCondition(now, 1234, `"username" and "groups" must be included in "allowedScopes" when "pinniped:request-audience" is included in "allowedScopes"`),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "pinniped:request-audience must be included in allowedScopes when urn:ietf:params:oauth:grant-type:token-exchange is included in allowedGrantTypes",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
					AllowedScopes:     []configv1alpha1.Scope{"openid"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Error",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						sadAllowedScopesCondition(now, 1234, `"pinniped:request-audience" must be included in "allowedScopes" when "urn:ietf:params:oauth:grant-type:token-exchange" is included in "allowedGrantTypes"`),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "successfully validate an OIDCClient with all allowedGrantTypes and all allowedScopes",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
					AllowedScopes:     []configv1alpha1.Scope{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						happyAllowedScopesCondition(now, 1234),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "successfully validate an OIDCClient for offline access without kube API access without username/groups",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code", "refresh_token"},
					AllowedScopes:     []configv1alpha1.Scope{"openid", "offline_access"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						happyAllowedScopesCondition(now, 1234),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "successfully validate an OIDCClient for offline access without kube API access with username",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code", "refresh_token"},
					AllowedScopes:     []configv1alpha1.Scope{"openid", "offline_access", "username"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						happyAllowedScopesCondition(now, 1234),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "successfully validate an OIDCClient for offline access without kube API access with groups",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code", "refresh_token"},
					AllowedScopes:     []configv1alpha1.Scope{"openid", "offline_access", "groups"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						happyAllowedScopesCondition(now, 1234),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "successfully validate an OIDCClient for offline access without kube API access with both username and groups",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code", "refresh_token"},
					AllowedScopes:     []configv1alpha1.Scope{"openid", "offline_access", "username", "groups"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						happyAllowedScopesCondition(now, 1234),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "successfully validate an OIDCClient without offline access without kube API access with username",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code"},
					AllowedScopes:     []configv1alpha1.Scope{"openid", "username"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						happyAllowedScopesCondition(now, 1234),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "successfully validate an OIDCClient without offline access without kube API access with groups",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code"},
					AllowedScopes:     []configv1alpha1.Scope{"openid", "username"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						happyAllowedScopesCondition(now, 1234),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
		{
			name: "successfully validate an OIDCClient without offline access without kube API access with both username and groups",
			inputObjects: []runtime.Object{&configv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Spec: configv1alpha1.OIDCClientSpec{
					AllowedGrantTypes: []configv1alpha1.GrantType{"authorization_code"},
					AllowedScopes:     []configv1alpha1.Scope{"openid", "username", "groups"},
				},
			}},
			inputSecrets:   []runtime.Object{testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost})},
			wantAPIActions: 1, // one update
			wantResultingOIDCClients: []configv1alpha1.OIDCClient{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
				Status: configv1alpha1.OIDCClientStatus{
					Phase: "Ready",
					Conditions: []metav1.Condition{
						happyAllowedGrantTypesCondition(now, 1234),
						happyAllowedScopesCondition(now, 1234),
						happyClientSecretsCondition(1, now, 1234),
					},
					TotalClientSecrets: 1,
				},
			}},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fakePinnipedClient := pinnipedfake.NewSimpleClientset(tt.inputObjects...)
			fakePinnipedClientForInformers := pinnipedfake.NewSimpleClientset(tt.inputObjects...)
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(fakePinnipedClientForInformers, 0)
			fakeKubeClient := kubernetesfake.NewSimpleClientset(tt.inputSecrets...)
			kubeInformers := kubeinformers.NewSharedInformerFactoryWithOptions(fakeKubeClient, 0)

			controller := NewOIDCClientWatcherController(
				fakePinnipedClient,
				kubeInformers.Core().V1().Secrets(),
				pinnipedInformers.Config().V1alpha1().OIDCClients(),
				controllerlib.WithInformer,
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			pinnipedInformers.Start(ctx.Done())
			kubeInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: controllerlib.Key{}}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			require.Len(t, fakePinnipedClient.Actions(), tt.wantAPIActions)

			actualOIDCClients, err := fakePinnipedClient.ConfigV1alpha1().OIDCClients(testNamespace).List(ctx, metav1.ListOptions{})
			require.NoError(t, err)

			// Assert on the expected Status of the OIDCClients. Preprocess them a bit so that they're easier to assert against.
			require.ElementsMatch(t, tt.wantResultingOIDCClients, normalizeOIDCClients(actualOIDCClients.Items, now))
		})
	}
}

func normalizeOIDCClients(oidcClients []configv1alpha1.OIDCClient, now metav1.Time) []configv1alpha1.OIDCClient {
	result := make([]configv1alpha1.OIDCClient, 0, len(oidcClients))
	for _, u := range oidcClients {
		normalized := u.DeepCopy()

		// We're only interested in comparing the status, so zero out the spec.
		normalized.Spec = configv1alpha1.OIDCClientSpec{}

		// Round down the LastTransitionTime values to `now` if they were just updated. This makes
		// it much easier to encode assertions about the expected timestamps.
		for i := range normalized.Status.Conditions {
			if time.Since(normalized.Status.Conditions[i].LastTransitionTime.Time) < 5*time.Second {
				normalized.Status.Conditions[i].LastTransitionTime = now
			}
		}
		result = append(result, *normalized)
	}

	return result
}
