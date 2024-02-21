// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package webhookcachefiller

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	clocktesting "k8s.io/utils/clock/testing"

	auth1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/conditionstestutil"
	"go.pinniped.dev/internal/testutil/testlogger"
)

func TestController(t *testing.T) {
	t.Parallel()

	goodEndpoint := "https://example.com"

	nowDoesntMatter := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
	frozenMetav1Now := metav1.NewTime(nowDoesntMatter)
	frozenClock := clocktesting.NewFakeClock(nowDoesntMatter)

	happyReadyCondition := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "Ready",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "the WebhookAuthenticator is ready",
		}
	}
	// sadReadyCondition := func(time metav1.Time, observedGeneration int64) metav1.Condition {
	// 	return metav1.Condition{
	// 		Type:               "Ready",
	// 		Status:             "False",
	// 		ObservedGeneration: observedGeneration,
	// 		LastTransitionTime: time,
	// 		Reason:             "NotReady",
	// 		Message:            "the WebhookAuthenticator is not ready: see other conditions for details",
	// 	}
	// }
	happyAuthenticatorValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "AuthenticatorValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "authenticator initialized",
		}
	}
	// unknownAuthenticatorValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
	// 	return metav1.Condition{
	// 		Type:               "AuthenticatorValid",
	// 		Status:             "Unknown",
	// 		ObservedGeneration: observedGeneration,
	// 		LastTransitionTime: time,
	// 		Reason:             "UnableToValidate",
	// 		Message:            "unable to validate; other issues present",
	// 	}
	// }
	// sadAuthenticatorValid := func() metav1.Condition {}

	happyTLSConfigurationValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConfigurationValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "valid TLS configuration",
		}
	}
	// sadTLSConfigurationValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
	// 	return metav1.Condition{
	// 		Type:               "TLSConfigurationValid",
	// 		Status:             "False",
	// 		ObservedGeneration: observedGeneration,
	// 		LastTransitionTime: time,
	// 		Reason:             "InvalidTLSConfiguration",
	// 		Message:            "invalid TLS configuration: illegal base64 data at input byte 7",
	// 	}
	// }

	happyEndpointURLValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "EndpointURLValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "endpoint is a valid URL",
		}
	}
	// happyEndpointURLValidInvalid := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
	// 	return metav1.Condition{
	// 		Type:               "EndpointURLValid",
	// 		Status:             "False",
	// 		ObservedGeneration: observedGeneration,
	// 		LastTransitionTime: time,
	// 		Reason:             "InvalidIssuerURL",
	// 		Message:            fmt.Sprintf(`spec.endpoint URL is invalid: parse "%s": invalid character " " in host name`, issuer),
	// 	}
	// }

	allHappyConditionsSuccess := func(endpoint string, someTime metav1.Time, observedGeneration int64) []metav1.Condition {

		return conditionstestutil.SortByType([]metav1.Condition{
			happyEndpointURLValid(someTime, observedGeneration),
			happyAuthenticatorValid(someTime, observedGeneration),
			happyReadyCondition(someTime, observedGeneration),
			happyTLSConfigurationValid(someTime, observedGeneration),
		})
	}

	tests := []struct {
		name                 string
		syncKey              controllerlib.Key
		webhooks             []runtime.Object
		wantErr              string
		wantLogs             []string
		wantStatusConditions []metav1.Condition
		wantStatusPhase      auth1alpha1.WebhookAuthenticatorPhase
		wantCacheEntries     int
	}{
		{
			name:    "404: webhook authenticator not found will abort sync loop and not write status",
			syncKey: controllerlib.Key{Name: "test-name"},
			// TODO(BEN): we lost this line when swapping loggers. Is that ok?
			//   did the JWTAuthenticator also lose it?  Should we ensure something exists otherwise?
			// wantLogs: []string{
			// 	`webhookcachefiller-controller "level"=0 "msg"="Sync() found that the WebhookAuthenticator does not exist yet or was deleted"`,
			// },
		},
		// Existing code that was never tested. We would likely have to create a server with bad clients to
		// simulate this.
		// { name: "non-404 `failed to get webhook authenticator` for other API server reasons" }
		{
			//  will fail sync loop and will report failed and unknown conditions and Error phase, but will not enqueue a resync due to user config error
			name:    "invalid webhook will fail the sync loop and........????",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: auth1alpha1.WebhookAuthenticatorSpec{
						Endpoint: "invalid url",
					},
				},
			},
			wantErr: `failed to build webhook config: parse "http://invalid url": invalid character " " in host name`,
		},
		// TODO (BEN): add valid without CA?
		{
			name: "valid webhook without CA...",
		}, {
			name: "",
		},
		{
			name:    "valid webhook will complete sync loop successfully with success conditions and ready phase",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: auth1alpha1.WebhookAuthenticatorSpec{
						Endpoint: goodEndpoint,
						TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: ""},
					},
				},
			},
			// TODO(BEN): we lost this changing loggers, make sure its captured in conditions
			// wantLogs: []string{
			// 	`webhookcachefiller-controller "level"=0 "msg"="added new webhook authenticator" "endpoint"="https://example.com" "webhook"={"name":"test-name"}`,
			// },
			wantStatusConditions: allHappyConditionsSuccess(goodEndpoint, frozenMetav1Now, 0),
			wantStatusPhase:      "Ready",
			wantCacheEntries:     1,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pinnipedAPIClient := pinnipedfake.NewSimpleClientset(tt.webhooks...)
			informers := pinnipedinformers.NewSharedInformerFactory(pinnipedAPIClient, 0)
			cache := authncache.New()
			testLog := testlogger.NewLegacy(t) //nolint:staticcheck  // old test with lots of log statements

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			controller := New(
				cache,
				pinnipedAPIClient,
				informers.Authentication().V1alpha1().WebhookAuthenticators(),
				frozenClock,
				logger)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			informers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: tt.syncKey}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantLogs, testLog.Lines(), "log lines should be correct")

			if tt.webhooks != nil {
				var webhookAuthSubject *auth1alpha1.WebhookAuthenticator
				getCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				webhookAuthSubject, getErr := pinnipedAPIClient.AuthenticationV1alpha1().WebhookAuthenticators().Get(getCtx, "test-name", metav1.GetOptions{})
				require.NoError(t, getErr)
				require.Equal(t, tt.wantStatusConditions, webhookAuthSubject.Status.Conditions, "status.conditions must be correct")
				require.Equal(t, tt.wantStatusPhase, webhookAuthSubject.Status.Phase, "status.phase should be correct")
			}

			require.Equal(t, tt.wantCacheEntries, len(cache.Keys()), fmt.Sprintf("expected cache entries is incorrect. wanted:%d, got: %d, keys: %v", tt.wantCacheEntries, len(cache.Keys()), cache.Keys()))
		})
	}
}

func TestNewWebhookAuthenticator(t *testing.T) {
	goodEndpoint := "https://example.com"

	t.Run("prerequisites not ready, cannot create webhook authenticator", func(t *testing.T) {
		conditions := []*metav1.Condition{}
		res, conditions, err := newWebhookAuthenticator(&auth1alpha1.WebhookAuthenticatorSpec{}, os.CreateTemp, clientcmd.WriteToFile, conditions, false)
		require.Equal(t, []*metav1.Condition{
			{
				Type:    "AuthenticatorValid",
				Status:  "Unknown",
				Reason:  "UnableToValidate",
				Message: "unable to validate; other issues present",
			},
		}, conditions)
		require.Nil(t, res)
		require.Nil(t, err)
	})

	t.Run("temp file failure, cannot create webhook authenticator", func(t *testing.T) {
		brokenTempFile := func(_ string, _ string) (*os.File, error) { return nil, fmt.Errorf("some temp file error") }
		conditions := []*metav1.Condition{}
		res, conditions, err := newWebhookAuthenticator(nil, brokenTempFile, clientcmd.WriteToFile, conditions, true)
		require.Equal(t, []*metav1.Condition{
			{
				Type:    "AuthenticatorValid",
				Status:  "False",
				Reason:  "UnableToCreateTempFile",
				Message: "unable to create temporary file: some temp file error",
			},
		}, conditions)
		require.Nil(t, res)
		require.EqualError(t, err, "unable to create temporary file: some temp file error")
	})

	t.Run("marshal failure, cannot create webhook authenticator", func(t *testing.T) {
		marshalError := func(_ clientcmdapi.Config, _ string) error { return fmt.Errorf("some marshal error") }
		conditions := []*metav1.Condition{}
		res, conditions, err := newWebhookAuthenticator(&auth1alpha1.WebhookAuthenticatorSpec{}, os.CreateTemp, marshalError, conditions, true)
		require.Equal(t, []*metav1.Condition{
			{
				Type:    "AuthenticatorValid",
				Status:  "False",
				Reason:  "UnableToMarshallKubeconfig",
				Message: "unable to marshal kubeconfig: some marshal error",
			},
		}, conditions)
		require.Nil(t, res)
		require.EqualError(t, err, "unable to marshal kubeconfig: some marshal error")
	})

	// t.Run("load kubeconfig err, not currently tested, may not be reasonable to test?")

	t.Run("invalid TLS config, base64 encoding err, cannot create webhook authenticator", func(t *testing.T) {
		conditions := []*metav1.Condition{}
		res, conditions, err := newWebhookAuthenticator(&auth1alpha1.WebhookAuthenticatorSpec{
			Endpoint: goodEndpoint,
			TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: "invalid-base64"},
		}, os.CreateTemp, clientcmd.WriteToFile, conditions, true)
		require.Equal(t, []*metav1.Condition{
			{
				Type:    "AuthenticatorValid",
				Status:  "False",
				Reason:  "InvalidTLSConfiguration",
				Message: "invalid TLS configuration: illegal base64 data at input byte 7",
			},
		}, conditions)
		require.Nil(t, res)
		// TODO: should this trigger the sync loop again with an error, or should this have been only
		// status and log, indicating user must correct?
		require.EqualError(t, err, "invalid TLS configuration: illegal base64 data at input byte 7")
	})

	t.Run("invalid pem data, cannot create webhook authenticator", func(t *testing.T) {
		conditions := []*metav1.Condition{}
		res, conditions, err := newWebhookAuthenticator(&auth1alpha1.WebhookAuthenticatorSpec{
			Endpoint: goodEndpoint,
			TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte("bad data"))},
		}, os.CreateTemp, clientcmd.WriteToFile, conditions, true)
		require.Equal(t, []*metav1.Condition{
			{
				Type:    "AuthenticatorValid",
				Status:  "False",
				Reason:  "InvalidTLSConfiguration",
				Message: "invalid TLS configuration: certificateAuthorityData is not valid PEM: data does not contain any valid RSA or ECDSA certificates",
			},
		}, conditions)
		require.Nil(t, res)
		require.EqualError(t, err, "invalid TLS configuration: certificateAuthorityData is not valid PEM: data does not contain any valid RSA or ECDSA certificates")
	})

	t.Run("valid config with no TLS spec, webhook authenticator created", func(t *testing.T) {
		conditions := []*metav1.Condition{}
		res, conditions, err := newWebhookAuthenticator(&auth1alpha1.WebhookAuthenticatorSpec{
			Endpoint: goodEndpoint,
		}, os.CreateTemp, clientcmd.WriteToFile, conditions, true)
		require.Equal(t, []*metav1.Condition{
			{
				Type:    "AuthenticatorValid",
				Status:  "True",
				Reason:  "Success",
				Message: "authenticator initialized",
			},
		}, conditions)
		require.NotNil(t, res)
		require.NoError(t, err)
	})

	t.Run("success, webhook authenticator created", func(t *testing.T) {
		// TODO(BEN): when enhancing webhook authenticator integration test, can prob
		// steal this and create a super simpler server
		caBundle, url := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.Contains(t, string(body), "test-token")
			_, err = w.Write([]byte(`{}`))
			require.NoError(t, err)
		})
		spec := &auth1alpha1.WebhookAuthenticatorSpec{
			Endpoint: url,
			TLS: &auth1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(caBundle)),
			},
		}
		conditions := []*metav1.Condition{}
		res, conditions, err := newWebhookAuthenticator(spec, os.CreateTemp, clientcmd.WriteToFile, conditions, true)
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Equal(t, []*metav1.Condition{
			{
				Type:    "AuthenticatorValid",
				Status:  "True",
				Reason:  "Success",
				Message: "authenticator initialized",
			},
		}, conditions)
		resp, authenticated, err := res.AuthenticateToken(context.Background(), "test-token")
		require.NoError(t, err)
		require.Nil(t, resp)
		require.False(t, authenticated)
	})
}
