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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	k8sinformers "k8s.io/client-go/informers"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	conciergefake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	conciergeinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controller/tlsconfigutil"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/mocks/mockcachevalue"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/conditionstestutil"
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

	hostAsLocalhostWebhookServer, _ := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// only expecting dials, which will not get into handler func
	}), func(s *httptest.Server) {
		s.TLS.Certificates = []tls.Certificate{*hostAsLocalhostServingCert}
		tlsserver.AssertEveryTLSHello(t, s, ptls.Default) // assert on every hello because we are only expecting dials
	})

	hostAs127001WebhookServer, _ := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// only expecting dials, which will not get into handler func
	}), func(s *httptest.Server) {
		s.TLS.Certificates = []tls.Certificate{*hostAs127001ServingCert}
		tlsserver.AssertEveryTLSHello(t, s, ptls.Default) // assert on every hello because we are only expecting dials
	})

	hostLocalWithExampleDotComCertServer, _ := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// only expecting dials, which will not get into handler func
	}), func(s *httptest.Server) {
		s.TLS.Certificates = []tls.Certificate{*localButExampleDotComServerCert}
		tlsserver.AssertEveryTLSHello(t, s, ptls.Default) // assert on every hello because we are only expecting dials
	})

	hostLocalIPv6Server, ipv6CA := tlsserver.TestServerIPv6(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), tlsserver.RecordTLSHello)

	mux := http.NewServeMux()
	mux.Handle("/nothing/here", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// note that we are only dialing, so we shouldn't actually get here
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, "404 nothing here")
	}))
	hostGoodDefaultServingCertServer, hostGoodDefaultServingCertServerCAPEM := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	}), func(s *httptest.Server) {
		tlsserver.AssertEveryTLSHello(t, s, ptls.Default) // assert on every hello because we are only expecting dials
	})
	hostGoodDefaultServingCertServerTLSSpec := &authenticationv1alpha1.TLSSpec{
		CertificateAuthorityData: base64.StdEncoding.EncodeToString(hostGoodDefaultServingCertServerCAPEM),
	}
	goodWebhookDefaultServingCertEndpoint := hostGoodDefaultServingCertServer.URL
	goodWebhookDefaultServingCertEndpointBut404 := goodWebhookDefaultServingCertEndpoint + "/nothing/here"

	localhostURL, err := url.Parse(hostAsLocalhostWebhookServer.URL)
	require.NoError(t, err)

	badEndpointInvalidURL := "https://.café   .com/café/café/café/coffee"
	badEndpointNoHTTPS := "http://localhost"

	nowDoesntMatter := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
	frozenMetav1Now := metav1.NewTime(nowDoesntMatter)
	frozenClock := clocktesting.NewFakeClock(nowDoesntMatter)

	timeInThePast := time.Date(1111, time.January, 1, 1, 1, 1, 111111, time.Local)
	frozenTimeInThePast := metav1.NewTime(timeInThePast)

	goodWebhookAuthenticatorSpecWithCA := authenticationv1alpha1.WebhookAuthenticatorSpec{
		Endpoint: goodWebhookDefaultServingCertEndpoint,
		TLS:      hostGoodDefaultServingCertServerTLSSpec,
	}
	goodWebhookAuthenticatorSpecWithCAFromSecret := authenticationv1alpha1.WebhookAuthenticatorSpec{
		Endpoint: goodWebhookDefaultServingCertEndpoint,
		TLS: &authenticationv1alpha1.TLSSpec{
			CertificateAuthorityDataSource: &authenticationv1alpha1.CABundleSource{
				Kind: "Secret",
				Name: "secret-with-ca",
				Key:  "ca.crt",
			},
		},
	}
	someSecretWithCA := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret-with-ca",
			Namespace: "concierge",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ca.crt": hostGoodDefaultServingCertServerCAPEM,
		},
	}
	goodWebhookAuthenticatorSpecWithCAFromConfigMap := authenticationv1alpha1.WebhookAuthenticatorSpec{
		Endpoint: goodWebhookDefaultServingCertEndpoint,
		TLS: &authenticationv1alpha1.TLSSpec{
			CertificateAuthorityDataSource: &authenticationv1alpha1.CABundleSource{
				Kind: "ConfigMap",
				Name: "configmap-with-ca",
				Key:  "ca.crt",
			},
		},
	}
	someConfigMapWithCA := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "configmap-with-ca",
			Namespace: "concierge",
		},
		Data: map[string]string{
			"ca.crt": string(hostGoodDefaultServingCertServerCAPEM),
		},
	}
	localWithExampleDotComWeebhookAuthenticatorSpec := authenticationv1alpha1.WebhookAuthenticatorSpec{
		// CA for example.com, TLS serving cert for example.com, but endpoint is still localhost
		Endpoint: hostLocalWithExampleDotComCertServer.URL,
		TLS: &authenticationv1alpha1.TLSSpec{
			// CA Bundle for example.com
			CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForExampleDotCom.Bundle()),
		},
	}
	goodWebhookAuthenticatorSpecWithoutCA := authenticationv1alpha1.WebhookAuthenticatorSpec{
		Endpoint: goodWebhookDefaultServingCertEndpoint,
		TLS:      &authenticationv1alpha1.TLSSpec{CertificateAuthorityData: ""},
	}
	goodWebhookAuthenticatorSpecWith404Endpoint := authenticationv1alpha1.WebhookAuthenticatorSpec{
		Endpoint: goodWebhookDefaultServingCertEndpointBut404,
		TLS:      hostGoodDefaultServingCertServerTLSSpec,
	}
	badWebhookAuthenticatorSpecInvalidTLS := authenticationv1alpha1.WebhookAuthenticatorSpec{
		Endpoint: goodWebhookDefaultServingCertEndpoint,
		TLS:      &authenticationv1alpha1.TLSSpec{CertificateAuthorityData: "invalid base64-encoded data"},
	}

	badWebhookAuthenticatorSpecGoodEndpointButUnknownCA := authenticationv1alpha1.WebhookAuthenticatorSpec{
		Endpoint: goodWebhookDefaultServingCertEndpoint,
		TLS: &authenticationv1alpha1.TLSSpec{
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
			Message:            "spec.tls is valid: using configured CA bundle",
		}
	}
	happyTLSConfigurationValidNoCA := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConfigurationValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "spec.tls is valid: no TLS configuration provided: using default root CA bundle from container image",
		}
	}
	sadTLSConfigurationValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "TLSConfigurationValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidTLSConfig",
			Message:            "spec.tls.certificateAuthorityData is invalid: illegal base64 data at input byte 7",
		}
	}

	happyWebhookConnectionValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "WebhookConnectionValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "successfully dialed webhook server",
		}
	}
	unknownWebhookConnectionValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "WebhookConnectionValid",
			Status:             "Unknown",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToValidate",
			Message:            "unable to validate; see other conditions for details",
		}
	}
	sadWebhookConnectionValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "WebhookConnectionValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToDialServer",
			Message:            "cannot dial server: tls: failed to verify certificate: x509: certificate signed by unknown authority",
		}
	}
	sadWebhookConnectionValidNoIPSANs := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "WebhookConnectionValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToDialServer",
			Message:            "cannot dial server: tls: failed to verify certificate: x509: cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs",
		}
	}
	sadWebhookConnectionValidWithMessage := func(time metav1.Time, observedGeneration int64, msg string) metav1.Condition {
		return metav1.Condition{
			Type:               "WebhookConnectionValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToDialServer",
			Message:            msg,
		}
	}

	happyEndpointURLValid := func(time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "EndpointURLValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "spec.endpoint is a valid URL",
		}
	}
	sadEndpointURLValid := func(issuer string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "EndpointURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidEndpointURL",
			Message:            fmt.Sprintf(`spec.endpoint URL cannot be parsed: parse "%s": invalid character " " in host name`, issuer),
		}
	}
	sadEndpointURLValidHTTPS := func(endpoint string, time metav1.Time, observedGeneration int64) metav1.Condition {
		return metav1.Condition{
			Type:               "EndpointURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidEndpointURLScheme",
			Message:            fmt.Sprintf(`spec.endpoint URL %s has invalid scheme, require 'https'`, endpoint),
		}
	}

	sadEndpointURLValidWithMessage := func(time metav1.Time, observedGeneration int64, msg string) metav1.Condition {
		return metav1.Condition{
			Type:               "EndpointURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidEndpointURL",
			Message:            msg,
		}
	}

	allHappyConditionsSuccess := func(endpoint string, someTime metav1.Time, observedGeneration int64) []metav1.Condition {
		return conditionstestutil.SortByType([]metav1.Condition{
			happyTLSConfigurationValidCAParsed(someTime, observedGeneration),
			happyEndpointURLValid(someTime, observedGeneration),
			happyWebhookConnectionValid(someTime, observedGeneration),
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
		name                  string
		cache                 func(*testing.T, *authncache.Cache)
		webhookAuthenticators []runtime.Object
		secretsAndConfigMaps  []runtime.Object
		// for modifying the clients to hack in arbitrary api responses
		configClient func(*conciergefake.Clientset)
		wantSyncErr  testutil.RequireErrorStringFunc
		wantLogs     []map[string]any
		wantActions  func() []coretesting.Action
		// random comment so lines above don't have huge indents
		wantNamesOfWebhookAuthenticatorsInCache []string
	}{
		{
			name: "Sync: No WebhookAuthenticators found results in no errors and no status conditions",
			wantLogs: []map[string]any{
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "webhookcachefiller-controller",
					"message":   "No WebhookAuthenticators found",
				},
			},
			wantActions: func() []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
				}
			},
			wantNamesOfWebhookAuthenticatorsInCache: []string{},
		},
		{
			name: "Sync: valid and unchanged WebhookAuthenticator: loop will preserve existing status conditions",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": false,
					"endpoint":    goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: multiple valid and multiple invalid WebhookAuthenticators",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "existing-webhook-authenticator",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "new-webhook-authenticator",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
				},
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "invalid-webhook-authenticator",
					},
					Spec: badWebhookAuthenticatorSpecInvalidTLS,
				},
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "another-invalid-webhook-authenticator",
					},
					Spec: badWebhookAuthenticatorSpecInvalidTLS,
				},
			},
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": false,
					"endpoint":         goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
						"name": "another-invalid-webhook-authenticator",
					},
				},
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": false,
					"endpoint":    goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
						"name": "existing-webhook-authenticator",
					},
				},
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": false,
					"endpoint":         goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
						"name": "invalid-webhook-authenticator",
					},
				},
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": false,
					"endpoint":    goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
						"name": "new-webhook-authenticator",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateValidStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "new-webhook-authenticator",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				})
				updateValidStatusAction.Subresource = "status"
				updateInvalidStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "invalid-webhook-authenticator",
					},
					Spec: badWebhookAuthenticatorSpecInvalidTLS,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadTLSConfigurationValid(frozenMetav1Now, 0),
								unknownWebhookConnectionValid(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateInvalidStatusAction.Subresource = "status"
				updateValidStatusAction.Subresource = "status"
				updateAnotherInvalidStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "another-invalid-webhook-authenticator",
					},
					Spec: badWebhookAuthenticatorSpecInvalidTLS,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadTLSConfigurationValid(frozenMetav1Now, 0),
								unknownWebhookConnectionValid(frozenMetav1Now, 0),
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
							},
						),
						Phase: "Error",
					},
				})
				updateAnotherInvalidStatusAction.Subresource = "status"
				return []coretesting.Action{
					coretesting.NewListAction(webhookAuthenticatorGVR, webhookAuthenticatorGVK, "", metav1.ListOptions{}),
					coretesting.NewWatchAction(webhookAuthenticatorGVR, "", metav1.ListOptions{}),
					updateAnotherInvalidStatusAction,
					updateInvalidStatusAction,
					updateValidStatusAction,
				}
			},
			wantNamesOfWebhookAuthenticatorsInCache: []string{
				"existing-webhook-authenticator",
				"new-webhook-authenticator",
			},
		},
		{
			name: "Sync: valid WebhookAuthenticator with CA from Secret: loop will complete successfully and update status conditions",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCAFromSecret,
				},
			},
			secretsAndConfigMaps: []runtime.Object{
				someSecretWithCA,
			},
			wantLogs: []map[string]any{
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": false,
					"endpoint":    goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCAFromSecret,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: valid WebhookAuthenticator with CA from ConfigMap: loop will complete successfully and update status conditions",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCAFromConfigMap,
				},
			},
			secretsAndConfigMaps: []runtime.Object{
				someConfigMapWithCA,
			},
			wantLogs: []map[string]any{
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": false,
					"endpoint":    goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCAFromConfigMap,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: valid WebhookAuthenticator with external and changed CA bundle: loop will complete successfully and update status conditions",
			cache: func(t *testing.T, cache *authncache.Cache) {
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "WebhookAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					newCacheValue(t, goodWebhookAuthenticatorSpecWithCAFromConfigMap, "some-stale-ca-bundle-pem-content-from-secret"),
				)
			},
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCAFromConfigMap,
				},
			},
			secretsAndConfigMaps: []runtime.Object{
				someConfigMapWithCA,
			},
			wantLogs: []map[string]any{
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": true,
					"endpoint":    goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCAFromConfigMap,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "previously valid cached authenticator (which did not specify a CA bundle) changes and becomes invalid due to any problem with the CA bundle: loop will fail sync, will write failed and unknown status conditions, and will remove authenticator from cache",
			cache: func(t *testing.T, cache *authncache.Cache) {
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "WebhookAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					// Force an invalid spec into the cache, which is not very realistic, but it simulates a case
					// where the CA bundle goes from being cached as empty to being an error during validation,
					// without causing any changes in the spec. This test wants to prove that the rest of the
					// validations get run and the resource is update, just in case that can happen somehow.
					newCacheValue(t, badWebhookAuthenticatorSpecInvalidTLS, ""),
				)
			},
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: badWebhookAuthenticatorSpecInvalidTLS,
				},
			},
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": true,
					"endpoint":         badWebhookAuthenticatorSpecInvalidTLS.Endpoint,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: badWebhookAuthenticatorSpecInvalidTLS,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadTLSConfigurationValid(frozenMetav1Now, 0),
								unknownWebhookConnectionValid(frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{},
		},
		{
			name: "Sync: valid and unchanged WebhookAuthenticator which was already cached: skips any updates to status or cache",
			cache: func(t *testing.T, cache *authncache.Cache) {
				oldCA, err := base64.StdEncoding.DecodeString(goodWebhookAuthenticatorSpecWithCA.TLS.CertificateAuthorityData)
				require.NoError(t, err)
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "WebhookAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					newCacheValue(t, goodWebhookAuthenticatorSpecWithCA, string(oldCA)),
				)
			},
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":     "info",
					"timestamp": "2099-08-08T13:57:36.123456Z",
					"logger":    "webhookcachefiller-controller",
					"message":   "cached webhook authenticator and desired webhook authenticator are the same: already cached, so skipping validations",
					"endpoint":  goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: authenticator update when cached authenticator is the wrong data type, which should never really happen: loop will complete successfully and update status conditions",
			cache: func(t *testing.T, cache *authncache.Cache) {
				ctrl := gomock.NewController(t)
				t.Cleanup(func() {
					ctrl.Finish()
				})
				mockCacheValue := mockcachevalue.NewMockValue(ctrl)
				mockCacheValue.EXPECT().Close().Times(1)
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "WebhookAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					// Only entries of type cachedWebhookAuthenticator are ever put into the cache, so this should never really happen.
					// This test is to provide coverage on the production code which reads from the cache and casts those entries to
					// the appropriate data type.
					mockCacheValue,
				)
			},
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
				},
			},
			wantLogs: []map[string]any{
				{
					"level":      "info",
					"timestamp":  "2099-08-08T13:57:36.123456Z",
					"logger":     "webhookcachefiller-controller",
					"message":    "wrong webhook authenticator type in cache",
					"actualType": "*mockcachevalue.MockValue",
				},
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": false,
					"endpoint":    goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: changed WebhookAuthenticator: loop will update timestamps only on relevant statuses",
			cache: func(t *testing.T, cache *authncache.Cache) {
				oldCA, err := base64.StdEncoding.DecodeString(goodWebhookAuthenticatorSpecWith404Endpoint.TLS.CertificateAuthorityData)
				require.NoError(t, err)
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "WebhookAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					newCacheValue(t, goodWebhookAuthenticatorSpecWith404Endpoint, string(oldCA)),
				)
			},
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-name",
						Generation: 1234,
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 1233),
							[]metav1.Condition{
								sadReadyCondition(frozenTimeInThePast, 1232),
								happyEndpointURLValid(frozenTimeInThePast, 1231),
							},
						),
						Phase: "Ready",
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": true,
					"endpoint":    goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-name",
						Generation: 1234,
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 1234),
							[]metav1.Condition{
								happyEndpointURLValid(frozenTimeInThePast, 1234),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: previously cached authenticator gets new valid spec fields, but status update fails: loop will leave it in the cache",
			cache: func(t *testing.T, cache *authncache.Cache) {
				oldCA, err := base64.StdEncoding.DecodeString(goodWebhookAuthenticatorSpecWith404Endpoint.TLS.CertificateAuthorityData)
				require.NoError(t, err)
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "WebhookAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					newCacheValue(t, goodWebhookAuthenticatorSpecWith404Endpoint, string(oldCA)),
				)
			},
			configClient: func(client *conciergefake.Clientset) {
				client.PrependReactor(
					"update",
					"webhookauthenticators",
					func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("some update error")
					},
				)
			},
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-name",
						Generation: 1234,
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
				},
			},
			wantLogs: []map[string]any{},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "test-name",
						Generation: 1234,
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 1234),
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
			wantSyncErr:                             testutil.WantExactErrorString("error for WebhookAuthenticator test-name: some update error"),
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"}, // keeps the old entry in the cache
		},
		{
			name: "Sync: valid WebhookAuthenticator with CA: will complete sync loop successfully with success conditions and ready phase",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
				},
			},
			wantLogs: []map[string]any{
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": false,
					"endpoint":    goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: valid WebhookAuthenticator with IPV6 and CA: will complete sync loop successfully with success conditions and ready phase",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: func() authenticationv1alpha1.WebhookAuthenticatorSpec {
						ipv6 := goodWebhookAuthenticatorSpecWithCA.DeepCopy()
						ipv6.Endpoint = hostLocalIPv6Server.URL
						ipv6.TLS = ptr.To(authenticationv1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(ipv6CA),
						})
						return *ipv6
					}(),
				},
			},
			wantLogs: []map[string]any{
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": false,
					"endpoint":    hostLocalIPv6Server.URL,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: func() authenticationv1alpha1.WebhookAuthenticatorSpec {
						ipv6 := goodWebhookAuthenticatorSpecWithCA.DeepCopy()
						ipv6.Endpoint = hostLocalIPv6Server.URL
						ipv6.TLS = ptr.To(authenticationv1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(ipv6CA),
						})
						return *ipv6
					}(),
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(hostLocalIPv6Server.URL, frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "Sync: valid WebhookAuthenticator without CA: loop will fail to cache the authenticator, will write failed and unknown status conditions, and will enqueue resync",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithoutCA,
				},
			},
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": false,
					"endpoint":         goodWebhookAuthenticatorSpecWithoutCA.Endpoint,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithoutCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyTLSConfigurationValidNoCA(frozenMetav1Now, 0),
								sadWebhookConnectionValid(frozenMetav1Now, 0),
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
			wantSyncErr:                             testutil.WantExactErrorString(`error for WebhookAuthenticator test-name: cannot dial server: tls: failed to verify certificate: x509: certificate signed by unknown authority`),
			wantNamesOfWebhookAuthenticatorsInCache: []string{},
		},
		{
			name: "validateTLS: WebhookAuthenticator with invalid CA will fail sync loop and will report failed and unknown conditions and Error phase, but will not enqueue a resync due to user config error",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: badWebhookAuthenticatorSpecInvalidTLS,
				},
			},
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": false,
					"endpoint":         badWebhookAuthenticatorSpecInvalidTLS.Endpoint,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: badWebhookAuthenticatorSpecInvalidTLS,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadTLSConfigurationValid(frozenMetav1Now, 0),
								unknownWebhookConnectionValid(frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{},
		},
		{
			name: "previously valid cached authenticator's spec changes and becomes invalid (e.g. spec.issuer URL is invalid): loop will fail sync, will write failed and unknown status conditions, and will remove authenticator from cache",
			cache: func(t *testing.T, cache *authncache.Cache) {
				oldCA, err := base64.StdEncoding.DecodeString(goodWebhookAuthenticatorSpecWithCA.TLS.CertificateAuthorityData)
				require.NoError(t, err)
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "WebhookAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					newCacheValue(t, goodWebhookAuthenticatorSpecWithCA, string(oldCA)),
				)
			},
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: badEndpointInvalidURL,
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": true,
					"endpoint":         badEndpointInvalidURL,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: badEndpointInvalidURL,
					},
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyTLSConfigurationValidNoCA(frozenMetav1Now, 0),
								sadEndpointURLValid("https://.café   .com/café/café/café/coffee", frozenMetav1Now, 0),
								unknownWebhookConnectionValid(frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{}, // removed from cache
		},
		{
			name: "previously valid cached authenticator's spec changes and becomes invalid (e.g. spec.issuer URL is invalid): loop will fail sync, will write failed and unknown status conditions, and will remove authenticator from cache even though the status update failed",
			cache: func(t *testing.T, cache *authncache.Cache) {
				oldCA, err := base64.StdEncoding.DecodeString(goodWebhookAuthenticatorSpecWithCA.TLS.CertificateAuthorityData)
				require.NoError(t, err)
				cache.Store(
					authncache.Key{
						Name:     "test-name",
						Kind:     "WebhookAuthenticator",
						APIGroup: authenticationv1alpha1.SchemeGroupVersion.Group,
					},
					newCacheValue(t, goodWebhookAuthenticatorSpecWithCA, string(oldCA)),
				)
			},
			configClient: func(client *conciergefake.Clientset) {
				client.PrependReactor(
					"update",
					"webhookauthenticators",
					func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("some update error")
					},
				)
			},
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: badEndpointInvalidURL,
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": true,
					"endpoint":         badEndpointInvalidURL,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: badEndpointInvalidURL,
					},
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyTLSConfigurationValidNoCA(frozenMetav1Now, 0),
								sadEndpointURLValid("https://.café   .com/café/café/café/coffee", frozenMetav1Now, 0),
								unknownWebhookConnectionValid(frozenMetav1Now, 0),
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
			wantSyncErr:                             testutil.WantExactErrorString("error for WebhookAuthenticator test-name: some update error"),
			wantNamesOfWebhookAuthenticatorsInCache: []string{}, // removed from cache
		},
		{
			name: "validateEndpoint: parsing error (spec.endpoint URL is invalid) will fail sync loop and will report failed and unknown conditions and Error phase, but will not enqueue a resync due to user config error",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: badEndpointInvalidURL,
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": false,
					"endpoint":         badEndpointInvalidURL,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: badEndpointInvalidURL,
					},
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyTLSConfigurationValidNoCA(frozenMetav1Now, 0),
								sadEndpointURLValid("https://.café   .com/café/café/café/coffee", frozenMetav1Now, 0),
								unknownWebhookConnectionValid(frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{},
		},
		{
			name: "validateEndpoint: parsing error (spec.endpoint URL has invalid scheme, requires https) will fail sync loop, will write failed and unknown status conditions, but will not enqueue a resync due to user config error",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: badEndpointNoHTTPS,
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": false,
					"endpoint":         badEndpointNoHTTPS,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: badEndpointNoHTTPS,
					},
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								happyTLSConfigurationValidNoCA(frozenMetav1Now, 0),
								sadEndpointURLValidHTTPS("http://localhost", frozenMetav1Now, 0),
								unknownWebhookConnectionValid(frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{},
		},
		{
			name: "validateEndpoint: should error if endpoint cannot be parsed",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: "https://[0:0:0:0:0:0:0:1]:69999/some/fake/path",
						TLS: &authenticationv1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForLocalhostAs127001.Bundle()),
						},
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": false,
					"endpoint":         "https://[0:0:0:0:0:0:0:1]:69999/some/fake/path",
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: "https://[0:0:0:0:0:0:0:1]:69999/some/fake/path",
						TLS: &authenticationv1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForLocalhostAs127001.Bundle()),
						},
					},
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess("https://[0:0:0:0:0:0:0:1]:69999/some/fake/path", frozenMetav1Now, 0),
							[]metav1.Condition{
								sadEndpointURLValidWithMessage(frozenMetav1Now, 0, `spec.endpoint URL is not valid: invalid port "69999"`),
								sadReadyCondition(frozenMetav1Now, 0),
								unknownWebhookConnectionValid(frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{},
		},
		{
			name: "validateConnection: CA does not validate serving certificate for host, the dialer will error, will fail sync loop, will write failed and unknown status conditions, but will not enqueue a resync due to user config error",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: badWebhookAuthenticatorSpecGoodEndpointButUnknownCA,
				},
			},
			wantSyncErr: testutil.WantExactErrorString("error for WebhookAuthenticator test-name: cannot dial server: tls: failed to verify certificate: x509: certificate signed by unknown authority"),
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": false,
					"endpoint":         badWebhookAuthenticatorSpecGoodEndpointButUnknownCA.Endpoint,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: badWebhookAuthenticatorSpecGoodEndpointButUnknownCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								unknownAuthenticatorValid(frozenMetav1Now, 0),
								sadReadyCondition(frozenMetav1Now, 0),
								sadWebhookConnectionValid(frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{},
		},
		// No unit test for system roots.  We don't test the WebhookAuthenticator's use of system roots either.
		// We would have to find a way to mock out roots by adding a dummy cert in order to test this
		// { name: "validateConnection: TLS bundle not provided should use system roots to validate server cert signed by a well-known CA",},
		{
			name: "validateConnection: 404 endpoint on a valid server will still validate server certificate, will complete sync loop successfully with success conditions and ready phase",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWith404Endpoint,
				},
			},
			wantLogs: []map[string]any{
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": false,
					"endpoint":    goodWebhookDefaultServingCertEndpointBut404,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWith404Endpoint,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpointBut404, frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "validateConnection: localhost hostname instead of 127.0.0.1 should still dial correctly as dialer should handle hostnames as well as IPv4",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: fmt.Sprintf("https://localhost:%s", localhostURL.Port()),
						TLS: &authenticationv1alpha1.TLSSpec{
							// CA Bundle for validating the server's certs
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForLocalhostAsHostname.Bundle()),
						},
					},
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(fmt.Sprintf("https://localhost:%s", localhostURL.Port()), frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": false,
					"endpoint":    fmt.Sprintf("https://localhost:%s", localhostURL.Port()),
					"webhookAuthenticator": map[string]any{
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "validateConnection: IPv6 address with port: should call dialer func with correct arguments",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: "https://[0:0:0:0:0:0:0:1]:4242/some/fake/path",
						TLS: &authenticationv1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForLocalhostAs127001.Bundle()),
						},
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": false,
					"endpoint":         "https://[0:0:0:0:0:0:0:1]:4242/some/fake/path",
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: "https://[0:0:0:0:0:0:0:1]:4242/some/fake/path",
						TLS: &authenticationv1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForLocalhostAs127001.Bundle()),
						},
					},
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess("https://[0:0:0:0:0:0:0:1]:4242/some/fake/path", frozenMetav1Now, 0),
							[]metav1.Condition{
								sadWebhookConnectionValidWithMessage(frozenMetav1Now, 0, "cannot dial server: dial tcp [::1]:4242: connect: connection refused"),
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
			wantSyncErr:                             testutil.WantExactErrorString(`error for WebhookAuthenticator test-name: cannot dial server: dial tcp [::1]:4242: connect: connection refused`),
			wantNamesOfWebhookAuthenticatorsInCache: []string{},
		},
		{
			name: "validateConnection: IPv6 address without port: should call dialer func with correct arguments",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: "https://[0:0:0:0:0:0:0:1]/some/fake/path",
						TLS: &authenticationv1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForLocalhostAs127001.Bundle()),
						},
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": false,
					"endpoint":         "https://[0:0:0:0:0:0:0:1]/some/fake/path",
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: "https://[0:0:0:0:0:0:0:1]/some/fake/path",
						TLS: &authenticationv1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForLocalhostAs127001.Bundle()),
						},
					},
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess("https://[0:0:0:0:0:0:0:1]/some/fake/path", frozenMetav1Now, 0),
							[]metav1.Condition{
								sadWebhookConnectionValidWithMessage(frozenMetav1Now, 0, "cannot dial server: dial tcp [::1]:443: connect: connection refused"),
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
			wantSyncErr:                             testutil.WantExactErrorString(`error for WebhookAuthenticator test-name: cannot dial server: dial tcp [::1]:443: connect: connection refused`),
			wantNamesOfWebhookAuthenticatorsInCache: []string{},
		},
		{
			name: "validateConnection: localhost as IP address 127.0.0.1 should still dial correctly as dialer should handle hostnames as well as IPv4 and IPv6 addresses",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: hostAs127001WebhookServer.URL,
						TLS: &authenticationv1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForLocalhostAs127001.Bundle()),
						},
					},
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(hostAs127001WebhookServer.URL, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": false,
					"endpoint":    hostAs127001WebhookServer.URL,
					"webhookAuthenticator": map[string]any{
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "validateConnection: CA for example.com, serving cert for example.com, but endpoint 127.0.0.1 will fail to validate certificate and will fail sync loop and will report failed and unknown conditions and Error phase, but will not enqueue a resync due to user config error",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: localWithExampleDotComWeebhookAuthenticatorSpec,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(hostLocalWithExampleDotComCertServer.URL, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": false,
					"endpoint":         localWithExampleDotComWeebhookAuthenticatorSpec.Endpoint,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: localWithExampleDotComWeebhookAuthenticatorSpec,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(hostLocalWithExampleDotComCertServer.URL, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadWebhookConnectionValidNoIPSANs(frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{},
			wantSyncErr:                             testutil.WantExactErrorString(`error for WebhookAuthenticator test-name: cannot dial server: tls: failed to verify certificate: x509: cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs`),
		},
		{
			name: "validateConnection: IPv6 address without port or brackets: should succeed since IPv6 brackets are optional without port",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: "https://0:0:0:0:0:0:0:1/some/fake/path",
						TLS: &authenticationv1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForLocalhostAs127001.Bundle()),
						},
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":            "info",
					"timestamp":        "2099-08-08T13:57:36.123456Z",
					"logger":           "webhookcachefiller-controller",
					"message":          "invalid webhook authenticator",
					"removedFromCache": false,
					"endpoint":         "https://0:0:0:0:0:0:0:1/some/fake/path",
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: authenticationv1alpha1.WebhookAuthenticatorSpec{
						Endpoint: "https://0:0:0:0:0:0:0:1/some/fake/path",
						TLS: &authenticationv1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(caForLocalhostAs127001.Bundle()),
						},
					},
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess("https://0:0:0:0:0:0:0:1/some/fake/path", frozenMetav1Now, 0),
							[]metav1.Condition{
								sadWebhookConnectionValidWithMessage(frozenMetav1Now, 0, "cannot dial server: dial tcp [::1]:443: connect: connection refused"),
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
			wantSyncErr:                             testutil.WantExactErrorString(`error for WebhookAuthenticator test-name: cannot dial server: dial tcp [::1]:443: connect: connection refused`),
			wantNamesOfWebhookAuthenticatorsInCache: []string{},
		},
		{
			name: "updateStatus: called with matching original and updated conditions: will not make request to update conditions",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
						Phase:      "Ready",
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": false,
					"endpoint":    goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "updateStatus: called with different original and updated conditions: will make request to update conditions",
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: conditionstestutil.Replace(
							allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
							[]metav1.Condition{
								sadReadyCondition(frozenMetav1Now, 0),
							},
						),
						Phase: "SomethingBeforeUpdating",
					},
				},
			},
			wantLogs: []map[string]any{
				{
					"level":       "info",
					"timestamp":   "2099-08-08T13:57:36.123456Z",
					"logger":      "webhookcachefiller-controller",
					"message":     "added or updated webhook authenticator in cache",
					"isOverwrite": false,
					"endpoint":    goodWebhookDefaultServingCertEndpoint,
					"webhookAuthenticator": map[string]any{
						"name": "test-name",
					},
				},
			},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
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
			wantNamesOfWebhookAuthenticatorsInCache: []string{"test-name"},
		},
		{
			name: "updateStatus: given a valid WebhookAuthenticator spec, when update request fails: error will enqueue a resync and the authenticator will not be added to the cache",
			configClient: func(client *conciergefake.Clientset) {
				client.PrependReactor(
					"update",
					"webhookauthenticators",
					func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("some update error")
					},
				)
			},
			webhookAuthenticators: []runtime.Object{
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
				},
			},
			wantLogs: []map[string]any{},
			wantActions: func() []coretesting.Action {
				updateStatusAction := coretesting.NewUpdateAction(webhookAuthenticatorGVR, "", &authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: goodWebhookAuthenticatorSpecWithCA,
					Status: authenticationv1alpha1.WebhookAuthenticatorStatus{
						Conditions: allHappyConditionsSuccess(goodWebhookDefaultServingCertEndpoint, frozenMetav1Now, 0),
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
			wantSyncErr:                             testutil.WantExactErrorString("error for WebhookAuthenticator test-name: some update error"),
			wantNamesOfWebhookAuthenticatorsInCache: []string{}, // even though the authenticator was valid, do not cache it because the status update failed
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pinnipedAPIClient := conciergefake.NewSimpleClientset(tt.webhookAuthenticators...)
			if tt.configClient != nil {
				tt.configClient(pinnipedAPIClient)
			}
			pinnipedInformers := conciergeinformers.NewSharedInformerFactory(pinnipedAPIClient, 0)
			kubeInformers := kubeinformers.NewSharedInformerFactory(kubernetesfake.NewSimpleClientset(tt.secretsAndConfigMaps...), 0)
			cache := authncache.New()

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			if tt.cache != nil {
				tt.cache(t, cache)
			}

			controller := New(
				"concierge", // namespace for controller
				cache,
				pinnipedAPIClient,
				pinnipedInformers.Authentication().V1alpha1().WebhookAuthenticators(),
				kubeInformers.Core().V1().Secrets(),
				kubeInformers.Core().V1().ConfigMaps(),
				controllerlib.WithInformer,
				frozenClock,
				logger)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			pinnipedInformers.Start(ctx.Done())
			kubeInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantSyncErr != nil {
				testutil.RequireErrorStringFromErr(t, err, tt.wantSyncErr)
			} else {
				require.NoError(t, err)
			}

			require.NotEmpty(t, tt.wantActions, "wantActions is required for test %s", tt.name)
			require.Equal(t, tt.wantActions(), pinnipedAPIClient.Actions())
			require.Equal(t, len(tt.wantNamesOfWebhookAuthenticatorsInCache), len(cache.Keys()), fmt.Sprintf("expected cache entries is incorrect. wanted:%d, got: %d, keys: %v", len(tt.wantNamesOfWebhookAuthenticatorsInCache), len(cache.Keys()), cache.Keys()))

			wantLogsAsJSON, err := json.Marshal(tt.wantLogs)
			require.NoError(t, err)

			actualLogLines := testutil.SplitByNewline(log.String())
			require.Equalf(t, len(tt.wantLogs), len(actualLogLines),
				"log line count should be correct\nactual: %s\nwant:   %s", actualLogLines, wantLogsAsJSON)

			for actualLogLineNum, actualLogLine := range actualLogLines {
				wantLine := tt.wantLogs[actualLogLineNum]
				require.NotNil(t, wantLine, "expected log line should never be empty")

				var actualParsedLine map[string]any
				err := json.Unmarshal([]byte(actualLogLine), &actualParsedLine)
				require.NoError(t, err)

				wantLineAsJSON, err := json.Marshal(wantLine)
				require.NoError(t, err)
				wantLine["caller"] = "we don't want to actually make equality comparisons about this"
				require.Lenf(t, actualParsedLine, len(wantLine), "actual: %s\nwant:   %s", actualLogLine, string(wantLineAsJSON))
				require.Equal(t, sets.StringKeySet(actualParsedLine), sets.StringKeySet(wantLine))

				for k := range actualParsedLine {
					if k == "caller" {
						require.NotEmpty(t, actualParsedLine["caller"])
					} else {
						require.Equal(t, wantLine[k], actualParsedLine[k],
							fmt.Sprintf("log line (%d) key %q was not equal\nactual: %s\nwant:   %s",
								actualLogLineNum, k, actualParsedLine[k], wantLine[k]))
					}
				}
			}
		})
	}
}

func TestNewWebhookAuthenticator(t *testing.T) {
	server, serverCA := tlsserver.TestServerIPv4(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Webhook clients should always use ptls.Default when making requests to the webhook. Assert that here.
			tlsserver.AssertTLS(t, r, ptls.Default)

			// Loosely assert on the request body.
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.Contains(t, string(body), "test-token")

			// Write a realistic looking fake response for a successfully authenticated user, so we can tell that
			// this endpoint was actually called by the test below where it asserts on the fake user and group names.
			w.Header().Add("Content-Type", "application/json")
			responseBody := authenticationv1beta1.TokenReview{
				TypeMeta: metav1.TypeMeta{
					Kind:       "TokenReview",
					APIVersion: authenticationv1beta1.SchemeGroupVersion.String(),
				},
				Status: authenticationv1beta1.TokenReviewStatus{
					Authenticated: true,
					User: authenticationv1beta1.UserInfo{
						Username: "fake-username-from-server",
						Groups:   []string{"fake-group-from-server-1", "fake-group-from-server-2"},
					},
				},
			}
			err = json.NewEncoder(w).Encode(responseBody)
			require.NoError(t, err)
		}),
		tlsserver.RecordTLSHello,
	)

	tests := []struct {
		name           string
		endpoint       string
		pemBytes       []byte
		prereqOk       bool
		wantConditions []*metav1.Condition
		wantErr        string
		wantWebhook    bool // When true, we want a webhook client to have been successfully created.
		callWebhook    bool // When true, really call the webhook endpoint using the created webhook client.
	}{
		{
			name:     "prerequisites not ready, cannot create webhook authenticator",
			endpoint: "",
			pemBytes: []byte("irrelevant pem bytes"),
			wantErr:  "",
			wantConditions: []*metav1.Condition{{
				Type:    "AuthenticatorValid",
				Status:  "Unknown",
				Reason:  "UnableToValidate",
				Message: "unable to validate; see other conditions for details",
			}},
			prereqOk: false,
		}, {
			name:     "invalid pem data, unable to parse bytes as PEM block",
			endpoint: "https://does-not-matter-will-not-be-used",
			pemBytes: []byte("invalid-bas64"),
			prereqOk: true,
			wantConditions: []*metav1.Condition{{
				Type:    "AuthenticatorValid",
				Status:  "False",
				Reason:  "UnableToCreateClient",
				Message: "unable to create client for this webhook: could not create secure client config: unable to load root certificates: unable to parse bytes as PEM block",
			}},
			wantErr: "unable to create client for this webhook: could not create secure client config: unable to load root certificates: unable to parse bytes as PEM block",
		}, {
			name:     "valid config with no PEM bytes, webhook authenticator created",
			endpoint: "https://does-not-matter-will-not-be-used",
			pemBytes: nil,
			prereqOk: true,
			wantConditions: []*metav1.Condition{{
				Type:    "AuthenticatorValid",
				Status:  "True",
				Reason:  "Success",
				Message: "authenticator initialized",
			}},
			wantWebhook: true,
		}, {
			name:     "valid config, webhook authenticator created, and test calling webhook server",
			endpoint: server.URL,
			pemBytes: serverCA,
			prereqOk: true,
			wantConditions: []*metav1.Condition{{
				Type:    "AuthenticatorValid",
				Status:  "True",
				Reason:  "Success",
				Message: "authenticator initialized",
			}},
			wantWebhook: true,
			callWebhook: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var conditions []*metav1.Condition
			webhook, conditions, err := newWebhookAuthenticator(tt.endpoint, tt.pemBytes, conditions, tt.prereqOk)

			require.Equal(t, tt.wantConditions, conditions)

			if tt.wantWebhook {
				require.NotNil(t, webhook)
			} else {
				require.Nil(t, webhook)
			}

			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			if tt.callWebhook {
				authResp, isAuthenticated, err := webhook.AuthenticateToken(context.Background(), "test-token")
				require.NoError(t, err)
				require.True(t, isAuthenticated)
				require.Equal(t, "fake-username-from-server", authResp.User.GetName())
				require.Equal(t, []string{"fake-group-from-server-1", "fake-group-from-server-2"}, authResp.User.GetGroups())
			}
		})
	}
}

func newCacheValue(t *testing.T, spec authenticationv1alpha1.WebhookAuthenticatorSpec, caBundle string) authncache.Value {
	t.Helper()

	return &cachedWebhookAuthenticator{
		spec:         &spec,
		caBundleHash: tlsconfigutil.NewCABundleHash([]byte(caBundle)),
	}
}

func TestControllerFilterSecret(t *testing.T) {
	tests := []struct {
		name       string
		secret     metav1.Object
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name: "should return true for a secret of the type Opaque",
			secret: &corev1.Secret{
				Type: corev1.SecretTypeOpaque,
				ObjectMeta: metav1.ObjectMeta{
					Name: "some-name",
				},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "should return true for a secret of the type TLS",
			secret: &corev1.Secret{
				Type: corev1.SecretTypeTLS,
				ObjectMeta: metav1.ObjectMeta{
					Name: "some-name",
				},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "should return false for a secret of the wrong type",
			secret: &corev1.Secret{
				Type: "other-type",
				ObjectMeta: metav1.ObjectMeta{
					Name: "some-name",
				},
			},
		},
		{
			name: "should return false for a resource of wrong data type",
			secret: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			nowDoesntMatter := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
			frozenClock := clocktesting.NewFakeClock(nowDoesntMatter)

			kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(kubernetesfake.NewSimpleClientset(), 0)
			secretInformer := kubeInformers.Core().V1().Secrets()
			configMapInformer := kubeInformers.Core().V1().ConfigMaps()
			pinnipedAPIClient := conciergefake.NewSimpleClientset()
			pinnipedInformers := conciergeinformers.NewSharedInformerFactory(pinnipedAPIClient, 0)
			observableInformers := testutil.NewObservableWithInformerOption()

			_ = New(
				"concierge", // namespace for controller
				authncache.New(),
				pinnipedAPIClient,
				pinnipedInformers.Authentication().V1alpha1().WebhookAuthenticators(),
				secretInformer,
				configMapInformer,
				observableInformers.WithInformer,
				frozenClock,
				logger)

			unrelated := &corev1.Secret{}
			filter := observableInformers.GetFilterForInformer(secretInformer)
			require.Equal(t, tt.wantAdd, filter.Add(tt.secret))
			require.Equal(t, tt.wantUpdate, filter.Update(unrelated, tt.secret))
			require.Equal(t, tt.wantUpdate, filter.Update(tt.secret, unrelated))
			require.Equal(t, tt.wantDelete, filter.Delete(tt.secret))
		})
	}
}

func TestControllerFilterConfigMap(t *testing.T) {
	namespace := "some-namespace"
	goodCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
		},
	}

	tests := []struct {
		name       string
		cm         metav1.Object
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name:       "a configMap in the right namespace",
			cm:         goodCM,
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			nowDoesntMatter := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
			frozenClock := clocktesting.NewFakeClock(nowDoesntMatter)

			kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(kubernetesfake.NewSimpleClientset(), 0)
			secretInformer := kubeInformers.Core().V1().Secrets()
			configMapInformer := kubeInformers.Core().V1().ConfigMaps()
			pinnipedAPIClient := conciergefake.NewSimpleClientset()
			pinnipedInformers := conciergeinformers.NewSharedInformerFactory(pinnipedAPIClient, 0)
			observableInformers := testutil.NewObservableWithInformerOption()

			_ = New(
				"concierge", // namespace for the controller
				authncache.New(),
				pinnipedAPIClient,
				pinnipedInformers.Authentication().V1alpha1().WebhookAuthenticators(),
				secretInformer,
				configMapInformer,
				observableInformers.WithInformer,
				frozenClock,
				logger)

			unrelated := &corev1.ConfigMap{}
			filter := observableInformers.GetFilterForInformer(configMapInformer)
			require.Equal(t, tt.wantAdd, filter.Add(tt.cm))
			require.Equal(t, tt.wantUpdate, filter.Update(unrelated, tt.cm))
			require.Equal(t, tt.wantUpdate, filter.Update(tt.cm, unrelated))
			require.Equal(t, tt.wantDelete, filter.Delete(tt.cm))
		})
	}
}
