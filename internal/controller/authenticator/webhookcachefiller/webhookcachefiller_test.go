// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package webhookcachefiller

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	clocktesting "k8s.io/utils/clock/testing"

	auth1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/conciergetestutil"
	"go.pinniped.dev/internal/testutil/conditionstestutil"
	"go.pinniped.dev/internal/testutil/stringutil"
	"go.pinniped.dev/internal/testutil/tlsserver"
)

func TestController(t *testing.T) {
	t.Parallel()

	caForLocalhostAsHostname, err := certauthority.New("My Localhost CA Common Name", time.Hour)
	require.NoError(t, err)
	onlyLocalhostAsHost := []string{"localhost"}
	noIPAddressesNotEven127001 := []net.IP{}
	hostAsLocalhostServingCert, err := caForLocalhostAsHostname.IssueServerCert(
		onlyLocalhostAsHost,
		noIPAddressesNotEven127001,
		time.Hour,
	)
	require.NoError(t, err)

	caForLocalhostAs127001, err := certauthority.New("My Localhost CA Common Name", time.Hour)
	require.NoError(t, err)
	noHostnameHost := []string{}
	only127001IPAddress := []net.IP{net.ParseIP("127.0.0.1")}
	hostAs127001ServingCert, err := caForLocalhostAs127001.IssueServerCert(
		noHostnameHost,
		only127001IPAddress,
		time.Hour,
	)
	require.NoError(t, err)

	caForUnknownServer, err := certauthority.New("Some Unknown CA", time.Hour)
	require.NoError(t, err)
	someUnknownHostNames := []string{"some-dns-name", "some-other-dns-name"}
	someLocalIPAddress := []net.IP{net.ParseIP("10.2.3.4")}
	pemServerCertForUnknownServer, _, err := caForUnknownServer.IssueServerCertPEM(
		someUnknownHostNames,
		someLocalIPAddress,
		time.Hour,
	)
	require.NoError(t, err)

	caForExampleDotCom, err := certauthority.New("Some Example.com CA", time.Hour)
	require.NoError(t, err)
	exampleDotComHostname := []string{"example.com"}
	localButExampleDotComServerCert, err := caForExampleDotCom.IssueServerCert(
		exampleDotComHostname,
		[]net.IP{},
		time.Hour,
	)
	require.NoError(t, err)

	hostAsLocalhostMux := http.NewServeMux()
	hostAsLocalhostWebhookServer := tlsserver.TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Default)
		hostAsLocalhostMux.ServeHTTP(w, r)
	}), func(thisServer *httptest.Server) {
		thisTLSConfig := ptls.Default(nil)
		thisTLSConfig.Certificates = []tls.Certificate{
			// public and private key pair, but server will only use private for serving
			*hostAsLocalhostServingCert,
		}
		thisServer.TLS = thisTLSConfig
	})

	hostAs127001Mux := http.NewServeMux()
	hostAs127001WebhookServer := tlsserver.TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Default)
		hostAs127001Mux.ServeHTTP(w, r)
	}), func(thisServer *httptest.Server) {
		thisTLSConfig := ptls.Default(nil)
		thisTLSConfig.Certificates = []tls.Certificate{
			*hostAs127001ServingCert,
		}
		thisServer.TLS = thisTLSConfig
	})

	localWithExampleDotComMux := http.NewServeMux()
	localWithExampleDotComCertServer := tlsserver.TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Default)
		localWithExampleDotComMux.ServeHTTP(w, r)
	}), func(thisServer *httptest.Server) {
		thisTLSConfig := ptls.Default(nil)
		thisTLSConfig.Certificates = []tls.Certificate{
			*localButExampleDotComServerCert,
		}
		thisServer.TLS = thisTLSConfig
	})

	goodMux := http.NewServeMux()
	goodWebhookServer := tlsserver.TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsserver.AssertTLS(t, r, ptls.Default)
		goodMux.ServeHTTP(w, r)
	}), tlsserver.RecordTLSHello)
	goodMux.Handle("/some/webhook", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := fmt.Fprintf(w, `{"something": "%s"}`, "something-for-response")
		require.NoError(t, err)
	}))
	goodMux.Handle("/nothing/here", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "404 nothing here")
	}))
	goodEndpoint := goodWebhookServer.URL
	goodEndpointBut404 := goodEndpoint + "/nothing/here"

	localhostURL, err := url.Parse(hostAsLocalhostWebhookServer.URL)
	require.NoError(t, err)
	localhostEndpointURL := fmt.Sprintf("%s:%s", "https://localhost", localhostURL.Port())

	badEndpoint := "https://.café   .com/café/café/café/coffee"
	badEndpointNoHTTPS := "http://localhost"

	nowDoesntMatter := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
	frozenMetav1Now := metav1.NewTime(nowDoesntMatter)
	frozenClock := clocktesting.NewFakeClock(nowDoesntMatter)

	timeInThePast := time.Date(1111, time.January, 1, 1, 1, 1, 111111, time.Local)
	frozenTimeInThePast := metav1.NewTime(timeInThePast)

	goodWebhookAuthenticatorSpecWithCA := auth1alpha1.WebhookAuthenticatorSpec{
		Endpoint: goodEndpoint,
		TLS:      conciergetestutil.TLSSpecFromTLSConfig(goodWebhookServer.TLS),
	}
	localhostWebhookAuthenticatorSpecWithCA := auth1alpha1.WebhookAuthenticatorSpec{
		Endpoint: localhostEndpointURL,
		TLS: &auth1alpha1.TLSSpec{
			// CA Bundle for validating the server's certs
			CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForLocalhostAsHostname.Bundle()),
		},
	}
	localWithExampleDotComWeebhookAuthenticatorSpec := auth1alpha1.WebhookAuthenticatorSpec{
		// CA for example.com, TLS serving cert for example.com, but endpoint is still localhost
		Endpoint: localWithExampleDotComCertServer.URL,
		TLS: &auth1alpha1.TLSSpec{
			// CA Bundle for example.com
			CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForExampleDotCom.Bundle()),
		},
	}
	goodWebhookAuthenticatorSpecWithoutCA := auth1alpha1.WebhookAuthenticatorSpec{
		Endpoint: goodEndpoint,
		TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: ""},
	}
	goodWebhookAuthenticatorSpecWith404Endpoint := auth1alpha1.WebhookAuthenticatorSpec{
		Endpoint: goodEndpointBut404,
		TLS:      conciergetestutil.TLSSpecFromTLSConfig(goodWebhookServer.TLS),
	}
	badWebhookAuthenticatorSpecInvalidTLS := auth1alpha1.WebhookAuthenticatorSpec{
		Endpoint: goodEndpoint,
		TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: "invalid base64-encoded data"},
	}

	badWebhookAuthenticatorSpecGoodEndpointButUnknownCA := auth1alpha1.WebhookAuthenticatorSpec{
		Endpoint: goodEndpoint,
		TLS: &auth1alpha1.TLSSpec{
			CertificateAuthorityData: base64.StdEncoding.EncodeToString(pemServerCertForUnknownServer),
		},
	}

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
	sadReadyCondition := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "Ready",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "NotReady",
			Message:            "the WebhookAuthenticator is not ready: see other conditions for details",
		}
	}
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
	unknownAuthenticatorValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "AuthenticatorValid",
			Status:             "Unknown",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToValidate",
			Message:            "unable to validate; see other conditions for details",
		}
	}

	happyTLSConfigurationValidCAParsed := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConfigurationValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "successfully parsed specified CA bundle",
		}
	}
	happyTLSConfigurationValidNoCA := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConfigurationValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "no CA bundle specified",
		}
	}
	sadTLSConfigurationValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConfigurationValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidTLSConfiguration",
			Message:            "invalid TLS configuration: illegal base64 data at input byte 7",
		}
	}

	happyTLSConnectionNegotiationValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConnectionNegotiationValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "tls verified",
		}
	}
	unknownTLSConnectionNegotiationValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConnectionNegotiationValid",
			Status:             "Unknown",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToValidate",
			Message:            "unable to validate; see other conditions for details",
		}
	}
	sadTLSConnectionNegotiationValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConnectionNegotiationValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToDialServer",
			Message:            "cannot dial server: tls: failed to verify certificate: x509: certificate signed by unknown authority",
		}
	}
	sadTLSConnectionNegotiationNoIPSANs := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConnectionNegotiationValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToDialServer",
			Message:            "cannot dial server: tls: failed to verify certificate: x509: cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs",
		}
	}

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
	sadEndpointURLValid := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "EndpointURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidEndpointURL",
			Message:            fmt.Sprintf(`spec.endpoint URL is invalid: parse "%s": invalid character " " in host name`, issuer),
		}
	}
	sadEndpointURLValidHTTPS := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "EndpointURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidEndpointURLScheme",
			Message:            fmt.Sprintf(`spec.endpoint %s has invalid scheme, require 'https'`, issuer),
		}
	}

	allHappyConditionsSuccess := func(endpoint string, someTime metav1.Time, observedGeneration int64) []metav1.Condition {
		return conditionstestutil.SortByType([]metav1.Condition{
			happyTLSConfigurationValidCAParsed(someTime, observedGeneration),
			happyEndpointURLValid(someTime, observedGeneration),
			happyTLSConnectionNegotiationValid(someTime, observedGeneration),
			happyAuthenticatorValid(someTime, observedGeneration),
			happyReadyCondition(someTime, observedGeneration),
		})
	}

	webhookAuthenticatorGVR := schema.GroupVersionResource{
		Group:    "authentication.concierge.pinniped.dev",
		Version:  "v1alpha1",
		Resource: "webhookauthenticators",
	}
	webhookAuthenticatorGVK := schema.GroupVersionKind{
		Group:   "authentication.concierge.pinniped.dev",
		Version: "v1alpha1",
		Kind:    "WebhookAuthenticator",
	}

	tests := []struct {
		name             string
		syncKey          controllerlib.Key
		webhooks         []runtime.Object
		tlsDialerFunc    func(network string, addr string, config *tls.Config) (*tls.Conn, error)
		wantSyncLoopErr  testutil.RequireErrorStringFunc
		wantLogs         []map[string]any
		wantActions      func() []coretesting.Action
		wantCacheEntries int
	}{
		{
			name:    "404: WebhookAuthenticator not found will abort sync loop, no status conditions",
			syncKey: controllerlib.Key{Name: "test-name"},
			wantLogs: []map[string]any{
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "webhookcachefiller-controller",
					"message":   "Sync() found that the WebhookAuthenticator does not exist yet or was deleted",
				},
			},
			wantActions: func() []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
				}
			},
			wantCacheEntries: 0,
		},
		// Existing code that was never tested. We would likely have to create a server with bad clients to
		// simulate this.
		// { name: "non-404 `failed to get webhook authenticator` for other API server reasons" }
		{
			name:    "Sync: valid and unchanged WebhookAuthenticator: loop will preserve existing status conditions",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodEndpoint, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "webhookcachefiller-controller",
					"message":   "added new webhook authenticator",
					"endpoint":  goodWebhookServer.URL,
					"webhook": map[string]interface{}{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
				}
			},
			wantCacheEntries: 1,
		}, {
			name:    "Sync: changed WebhookAuthenticator: loop will update timestamps only on relevant statuses",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadReadyCondition(frozenTimeInThePast, 0),
								happyEndpointURLValid(frozenTimeInThePast, 0),
							},
						),
						Phase: "Ready",
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "webhookcachefiller-controller",
					"message":   "added new webhook authenticator",
					"endpoint":  goodWebhookServer.URL,
					"webhook": map[string]interface{}{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyEndpointURLValid(frozenTimeInThePast, 0),
							},
						),
						Phase: "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantCacheEntries: 1,
		}, {
			name:    "Sync: valid WebhookAuthenticator with CA: will complete sync loop successfully with success conditions and ready phase",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
				},
			},
			wantLogs: []map[string]any{
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "webhookcachefiller-controller",
					"message":   "added new webhook authenticator",
					"endpoint":  goodWebhookServer.URL,
					"webhook": map[string]interface{}{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodEndpoint, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantCacheEntries: 1,
		},
		{
			name:    "Sync: valid WebhookAuthenticator without CA: loop will fail to cache the authenticator, will write failed and unknown status conditions, and will enqueue resync",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithoutCA,
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithoutCA,
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyTLSConfigurationValidNoCA(frozenMetav1Now, 0),
								sadTLSConnectionNegotiationValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantSyncLoopErr:  testutil.WantExactErrorString(`cannot dial server: tls: failed to verify certificate: x509: certificate signed by unknown authority`),
			wantCacheEntries: 0,
		},
		{
			name:    "validateTLS: WebhookAuthenticator with invalid CA will fail sync loop and will report failed and unknown conditions and Error phase, but will not enqueue a resync due to user config error",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: badWebhookAuthenticatorSpecInvalidTLS,
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: badWebhookAuthenticatorSpecInvalidTLS,
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadTLSConfigurationValid(frozenMetav1Now, 0),
								unknownTLSConnectionNegotiationValid(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantCacheEntries: 0,
		},
		{
			name:    "validateEndpoint: parsing error (spec.endpoint URL is invalid) will fail sync loop and will report failed and unknown conditions and Error phase, but will not enqueue a resync due to user config error",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: auth1alpha1.WebhookAuthenticatorSpec{
						Endpoint: badEndpoint,
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: auth1alpha1.WebhookAuthenticatorSpec{
						Endpoint: badEndpoint,
					},
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyTLSConfigurationValidNoCA(frozenMetav1Now, 0),
								sadEndpointURLValid("https://.café   .com/café/café/café/coffee", frozenMetav1Now, 0),
								unknownTLSConnectionNegotiationValid(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantCacheEntries: 0,
		}, {
			name:    "validateEndpoint: parsing error (spec.endpoint URL has invalid scheme, requires https) will fail sync loop, will write failed and unknown status conditions, but will not enqueue a resync due to user config error",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: auth1alpha1.WebhookAuthenticatorSpec{
						Endpoint: badEndpointNoHTTPS,
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: auth1alpha1.WebhookAuthenticatorSpec{
						Endpoint: badEndpointNoHTTPS,
					},
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyTLSConfigurationValidNoCA(frozenMetav1Now, 0),
								sadEndpointURLValidHTTPS("http://localhost", frozenMetav1Now, 0),
								unknownTLSConnectionNegotiationValid(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantCacheEntries: 0,
		},
		{
			name:    "validateTLSNegotiation: CA does not validate serving certificate for host, the dialer will error, will fail sync loop, will write failed and unknown status conditions, but will not enqueue a resync due to user config error",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: badWebhookAuthenticatorSpecGoodEndpointButUnknownCA,
				},
			},
			wantSyncLoopErr: testutil.WantExactErrorString("cannot dial server: tls: failed to verify certificate: x509: certificate signed by unknown authority"),
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: badWebhookAuthenticatorSpecGoodEndpointButUnknownCA,
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
								sadTLSConnectionNegotiationValid(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantCacheEntries: 0,
		},
		// No unit test for system roots.  We don't test the JWTAuthenticator's use of system roots either.
		// We would have to find a way to mock out roots by adding a dummy cert in order to test this
		// { name: "validateTLSNegotiation: TLS bundle not provided should use system roots to validate server cert signed by a well-known CA",},
		{
			name:    "validateTLSNegotiation: 404 endpoint on a valid server will still validate server certificate, will complete sync loop successfully with success conditions and ready phase",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWith404Endpoint,
				},
			},
			wantLogs: []map[string]any{
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "webhookcachefiller-controller",
					"message":   "added new webhook authenticator",
					"endpoint":  goodEndpointBut404,
					"webhook": map[string]interface{}{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWith404Endpoint,
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodEndpointBut404, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantCacheEntries: 1,
		}, {
			name:    "validateTLSNegotiation: localhost hostname instead of 127.0.0.1 should still dial correctly as dialer should handle hostnames as well as IPv4 and IPv6 addresses",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: localhostWebhookAuthenticatorSpecWithCA,
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(localhostEndpointURL, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "webhookcachefiller-controller",
					"message":   "added new webhook authenticator",
					"endpoint":  localhostEndpointURL,
					"webhook": map[string]interface{}{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
				}
			},
			wantCacheEntries: 1,
		}, {
			name:    "validateTLSNegotiation: localhost as IP address 127.0.0.1 should still dial correctly as dialer should handle hostnames as well as IPv4 and IPv6 addresses",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: auth1alpha1.WebhookAuthenticatorSpec{
						Endpoint: hostAs127001WebhookServer.URL,
						TLS: &auth1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForLocalhostAs127001.Bundle()),
						},
					},
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(hostAs127001WebhookServer.URL, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "webhookcachefiller-controller",
					"message":   "added new webhook authenticator",
					"endpoint":  hostAs127001WebhookServer.URL,
					"webhook": map[string]interface{}{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
				}
			},
			wantCacheEntries: 1,
		}, {
			name:    "validateTLSNegotiation: CA for example.com, serving cert for example.com, but endpoint 127.0.0.1 will fail to validate certificate and will fail sync loop and will report failed and unknown conditions and Error phase, but will not enqueue a resync due to user config error",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: localWithExampleDotComWeebhookAuthenticatorSpec,
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(localWithExampleDotComCertServer.URL, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: localWithExampleDotComWeebhookAuthenticatorSpec,
					Status: auth1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(localWithExampleDotComCertServer.URL, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadTLSConnectionNegotiationNoIPSANs(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
					updateStatusAction,
				}
			},
			wantCacheEntries: 0,
			wantSyncLoopErr:  testutil.WantExactErrorString(`cannot dial server: tls: failed to verify certificate: x509: cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs`),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pinnipedAPIClient := pinnipedfake.NewSimpleClientset(tt.webhooks...)
			informers := pinnipedinformers.NewSharedInformerFactory(pinnipedAPIClient, 0)
			cache := authncache.New()

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			if tt.tlsDialerFunc == nil {
				tt.tlsDialerFunc = tls.Dial
			}
			controller := New(
				cache,
				pinnipedAPIClient,
				informers.Authentication().V1alpha1().WebhookAuthenticators(),
				frozenClock,
				logger,
				tt.tlsDialerFunc)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			informers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: tt.syncKey}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantSyncLoopErr != nil {
				testutil.RequireErrorStringFromErr(t, err, tt.wantSyncLoopErr)
			} else {
				require.NoError(t, err)
			}
			actualLogLines := stringutil.SplitByNewline(log.String())
			require.Equal(t, len(actualLogLines), len(tt.wantLogs), "log line count should be correct")

			for logLineNum, logLine := range actualLogLines {
				require.NotNil(t, tt.wantLogs[logLineNum], "expected log line should never be empty")
				var lineStruct map[string]any
				err := json.Unmarshal([]byte(logLine), &lineStruct)
				require.NoError(t, err)
				require.Equal(t, tt.wantLogs[logLineNum]["level"], lineStruct["level"], fmt.Sprintf("log line (%d) log level should be correct (in: %s)", logLineNum, lineStruct))

				require.Equal(t, tt.wantLogs[logLineNum]["timestamp"], lineStruct["timestamp"], fmt.Sprintf("log line (%d) timestamp should be correct (in: %s)", logLineNum, lineStruct))
				require.Equal(t, lineStruct["logger"], tt.wantLogs[logLineNum]["logger"], fmt.Sprintf("log line (%d) logger should be correct", logLineNum))
				require.NotEmpty(t, lineStruct["caller"], fmt.Sprintf("log line (%d) caller should not be empty", logLineNum))
				require.Equal(t, tt.wantLogs[logLineNum]["message"], lineStruct["message"], fmt.Sprintf("log line (%d) message should be correct", logLineNum))
				if lineStruct["webhook"] != nil {
					require.Equal(t, tt.wantLogs[logLineNum]["webhook"], lineStruct["webhook"], fmt.Sprintf("log line (%d) webhook should be correct", logLineNum))
				}
				if lineStruct["endpoint"] != nil {
					require.Equal(t, tt.wantLogs[logLineNum]["endpoint"], lineStruct["endpoint"], fmt.Sprintf("log line (%d) endpoint should be correct", logLineNum))
				}
			}

			if tt.wantActions != nil {
				if !assert.ElementsMatch(t, tt.wantActions(), pinnipedAPIClient.Actions()) {
					// cmp.Diff is superior to require.ElementsMatch in terms of readability here.
					// require.ElementsMatch will handle pointers better than require.Equal, but
					// the timestamps are still incredibly verbose.
					require.Fail(t, cmp.Diff(tt.wantActions(), pinnipedAPIClient.Actions()), "actions should be exactly the expected number of actions and also contain the correct resources")
				}
			} else {
				require.Error(t, errors.New("wantActions is required for test "+tt.name))
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
				Message: "unable to validate; see other conditions for details",
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

	// t.Run("load kubeconfig err, not currently tested, may not be necessary to test?")

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
