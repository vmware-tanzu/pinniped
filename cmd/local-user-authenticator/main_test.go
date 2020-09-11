/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubeinformers "k8s.io/client-go/informers"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"

	"github.com/suzerain-io/pinniped/internal/certauthority"
	"github.com/suzerain-io/pinniped/internal/provider"
)

func TestWebhook(t *testing.T) {
	t.Parallel()

	const namespace = "local-user-authenticator"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	user, otherUser, colonUser, noGroupUser, oneGroupUser, passwordUndefinedUser, emptyPasswordUser, invalidPasswordHashUser, undefinedGroupsUser :=
		"some-user", "other-user", "colon-user", "no-group-user", "one-group-user", "password-undefined-user", "empty-password-user", "invalid-password-hash-user", "undefined-groups-user"
	uid, otherUID, colonUID, noGroupUID, oneGroupUID, passwordUndefinedUID, emptyPasswordUID, invalidPasswordHashUID, undefinedGroupsUID :=
		"some-uid", "other-uid", "colon-uid", "no-group-uid", "one-group-uid", "password-undefined-uid", "empty-password-uid", "invalid-password-hash-uid", "undefined-groups-uid"
	password, otherPassword, colonPassword, noGroupPassword, oneGroupPassword, undefinedGroupsPassword :=
		"some-password", "other-password", "some-:-password", "no-group-password", "one-group-password", "undefined-groups-password"

	group0, group1 := "some-group-0", "some-group-1"
	groups := group0 + " , " + group1

	kubeClient := kubernetesfake.NewSimpleClientset()
	addSecretToFakeClientTracker(t, kubeClient, user, uid, password, groups)
	addSecretToFakeClientTracker(t, kubeClient, otherUser, otherUID, otherPassword, groups)
	addSecretToFakeClientTracker(t, kubeClient, colonUser, colonUID, colonPassword, groups)
	addSecretToFakeClientTracker(t, kubeClient, noGroupUser, noGroupUID, noGroupPassword, "")
	addSecretToFakeClientTracker(t, kubeClient, oneGroupUser, oneGroupUID, oneGroupPassword, group0)
	addSecretToFakeClientTracker(t, kubeClient, emptyPasswordUser, emptyPasswordUID, "", groups)

	require.NoError(t, kubeClient.Tracker().Add(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			UID:       types.UID(passwordUndefinedUID),
			Name:      passwordUndefinedUser,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"groups": []byte(groups),
		},
	}))

	undefinedGroupsUserPasswordHash, err := bcrypt.GenerateFromPassword([]byte(undefinedGroupsPassword), bcrypt.MinCost)
	require.NoError(t, err)

	require.NoError(t, kubeClient.Tracker().Add(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			UID:       types.UID(undefinedGroupsUID),
			Name:      undefinedGroupsUser,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"passwordHash": undefinedGroupsUserPasswordHash,
		},
	}))

	require.NoError(t, kubeClient.Tracker().Add(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			UID:       types.UID(invalidPasswordHashUID),
			Name:      invalidPasswordHashUser,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"groups":       []byte(groups),
			"passwordHash": []byte("not a valid password hash"),
		},
	}))

	secretInformer := createSecretInformer(t, kubeClient)

	certProvider, caBundle, serverName := newCertProvider(t)
	w := newWebhook(certProvider, secretInformer)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	require.NoError(t, w.start(ctx, l))

	client := newClient(caBundle, serverName)

	goodURL := fmt.Sprintf("https://%s/authenticate", l.Addr().String())
	goodRequestHeaders := map[string][]string{
		"Content-Type": {"application/json; charset=UTF-8"},
		"Accept":       {"application/json, */*"},
	}

	tests := []struct {
		name    string
		url     string
		method  string
		headers map[string][]string
		body    func() (io.ReadCloser, error)

		wantStatus  int
		wantHeaders map[string][]string
		wantBody    *string
	}{
		{
			name:        "success for a user who belongs to multiple groups",
			url:         goodURL,
			method:      http.MethodPost,
			headers:     goodRequestHeaders,
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody(user + ":" + password) },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    authenticatedResponseJSON(user, uid, []string{group0, group1}),
		},
		{
			name:        "success for a user who belongs to one groups",
			url:         goodURL,
			method:      http.MethodPost,
			headers:     goodRequestHeaders,
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody(oneGroupUser + ":" + oneGroupPassword) },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    authenticatedResponseJSON(oneGroupUser, oneGroupUID, []string{group0}),
		},
		{
			name:        "success for a user who belongs to no groups",
			url:         goodURL,
			method:      http.MethodPost,
			headers:     goodRequestHeaders,
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody(noGroupUser + ":" + noGroupPassword) },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    authenticatedResponseJSON(noGroupUser, noGroupUID, []string{}),
		},
		{
			name:        "wrong username for password",
			url:         goodURL,
			method:      http.MethodPost,
			headers:     goodRequestHeaders,
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody(otherUser + ":" + password) },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    unauthenticatedResponseJSON(),
		},
		{
			name:        "when a user has no password hash in the secret",
			url:         goodURL,
			method:      http.MethodPost,
			headers:     goodRequestHeaders,
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody(passwordUndefinedUser + ":foo") },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    unauthenticatedResponseJSON(),
		},
		{
			name:        "when a user has an invalid password hash in the secret",
			url:         goodURL,
			method:      http.MethodPost,
			headers:     goodRequestHeaders,
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody(invalidPasswordHashUser + ":foo") },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    unauthenticatedResponseJSON(),
		},
		{
			name:    "success for a user has no groups defined in the secret",
			url:     goodURL,
			method:  http.MethodPost,
			headers: goodRequestHeaders,
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody(undefinedGroupsUser + ":" + undefinedGroupsPassword)
			},
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    authenticatedResponseJSON(undefinedGroupsUser, undefinedGroupsUID, []string{}),
		},
		{
			name:        "when a user has empty string as their password",
			url:         goodURL,
			method:      http.MethodPost,
			headers:     goodRequestHeaders,
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody(passwordUndefinedUser + ":foo") },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    unauthenticatedResponseJSON(),
		},
		{
			name:        "wrong password for username",
			url:         goodURL,
			method:      http.MethodPost,
			headers:     goodRequestHeaders,
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody(user + ":" + otherPassword) },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    unauthenticatedResponseJSON(),
		},
		{
			name:        "non-existent password for username",
			url:         goodURL,
			method:      http.MethodPost,
			headers:     goodRequestHeaders,
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody(user + ":" + "some-non-existent-password") },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    unauthenticatedResponseJSON(),
		},
		{
			name:        "non-existent username",
			url:         goodURL,
			method:      http.MethodPost,
			headers:     goodRequestHeaders,
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody("some-non-existent-user" + ":" + password) },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    unauthenticatedResponseJSON(),
		},
		{
			name:       "bad token format (missing colon)",
			url:        goodURL,
			method:     http.MethodPost,
			headers:    goodRequestHeaders,
			body:       func() (io.ReadCloser, error) { return newTokenReviewBody(user) },
			wantStatus: http.StatusBadRequest,
		},
		{
			name:        "password contains colon",
			url:         goodURL,
			method:      http.MethodPost,
			headers:     goodRequestHeaders,
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody(colonUser + ":" + colonPassword) },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    authenticatedResponseJSON(colonUser, colonUID, []string{group0, group1}),
		},
		{
			name:    "bad TokenReview group",
			url:     goodURL,
			method:  http.MethodPost,
			headers: goodRequestHeaders,
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody(
					user+":"+password,
					"wrong-group/v1",
				)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:    "bad TokenReview version",
			url:     goodURL,
			method:  http.MethodPost,
			headers: goodRequestHeaders,
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody(
					user+":"+password,
					"authentication.k8s.io/wrong-version",
				)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:    "bad TokenReview kind",
			url:     goodURL,
			method:  http.MethodPost,
			headers: goodRequestHeaders,
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody(
					user+":"+password,
					authenticationv1.SchemeGroupVersion.String(),
					"wrong-kind",
				)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "bad path",
			url:        fmt.Sprintf("https://%s/tuna", l.Addr().String()),
			method:     http.MethodPost,
			headers:    goodRequestHeaders,
			body:       func() (io.ReadCloser, error) { return newTokenReviewBody("some-token") },
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "bad method",
			url:        goodURL,
			method:     http.MethodGet,
			headers:    goodRequestHeaders,
			body:       func() (io.ReadCloser, error) { return newTokenReviewBody("some-token") },
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:   "bad content type",
			url:    goodURL,
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": {"application/xml"},
				"Accept":       {"application/json"},
			},
			body:       func() (io.ReadCloser, error) { return newTokenReviewBody("some-token") },
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:   "bad accept",
			url:    goodURL,
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": {"application/json"},
				"Accept":       {"application/xml"},
			},
			body:       func() (io.ReadCloser, error) { return newTokenReviewBody("some-token") },
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:   "success when there are multiple accepts and one of them is json",
			url:    goodURL,
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": {"application/json"},
				"Accept":       {"something/else, application/xml, application/json"},
			},
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody(user + ":" + password) },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    authenticatedResponseJSON(user, uid, []string{group0, group1}),
		},
		{
			name:   "success when there are multiple accepts and one of them is */*",
			url:    goodURL,
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": {"application/json"},
				"Accept":       {"something/else, */*, application/foo"},
			},
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody(user + ":" + password) },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    authenticatedResponseJSON(user, uid, []string{group0, group1}),
		},
		{
			name:   "success when there are multiple accepts and one of them is application/*",
			url:    goodURL,
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": {"application/json"},
				"Accept":       {"something/else, application/*, application/foo"},
			},
			body:        func() (io.ReadCloser, error) { return newTokenReviewBody(user + ":" + password) },
			wantStatus:  http.StatusOK,
			wantHeaders: map[string][]string{"Content-Type": {"application/json"}},
			wantBody:    authenticatedResponseJSON(user, uid, []string{group0, group1}),
		},
		{
			name:       "bad body",
			url:        goodURL,
			method:     http.MethodPost,
			headers:    goodRequestHeaders,
			body:       func() (io.ReadCloser, error) { return ioutil.NopCloser(bytes.NewBuffer([]byte("invalid body"))), nil },
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			parsedURL, err := url.Parse(test.url)
			require.NoError(t, err)

			body, err := test.body()
			require.NoError(t, err)

			rsp, err := client.Do(&http.Request{
				Method: test.method,
				URL:    parsedURL,
				Header: test.headers,
				Body:   body,
			})
			require.NoError(t, err)
			defer rsp.Body.Close()

			require.Equal(t, test.wantStatus, rsp.StatusCode)

			if test.wantHeaders != nil {
				for k, v := range test.wantHeaders {
					require.Equal(t, v, rsp.Header.Values(k))
				}
			}

			responseBody, err := ioutil.ReadAll(rsp.Body)
			require.NoError(t, err)
			if test.wantBody != nil {
				require.NoError(t, err)
				require.JSONEq(t, *test.wantBody, string(responseBody))
			} else {
				require.Empty(t, responseBody)
			}
		})
	}
}

func createSecretInformer(t *testing.T, kubeClient kubernetes.Interface) corev1informers.SecretInformer {
	t.Helper()

	kubeInformers := kubeinformers.NewSharedInformerFactory(kubeClient, 0)

	secretInformer := kubeInformers.Core().V1().Secrets()

	// We need to call Informer() on the secretInformer to lazily instantiate the
	// informer factory before syncing it.
	secretInformer.Informer()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	kubeInformers.Start(ctx.Done())

	informerTypesSynced := kubeInformers.WaitForCacheSync(ctx.Done())
	require.True(t, informerTypesSynced[reflect.TypeOf(&corev1.Secret{})])

	return secretInformer
}

// newClientProvider returns a provider.DynamicTLSServingCertProvider configured
// with valid serving cert, the CA bundle that can be used to verify the serving
// cert, and the server name that can be used to verify the TLS peer.
func newCertProvider(t *testing.T) (provider.DynamicTLSServingCertProvider, []byte, string) {
	t.Helper()

	serverName := "local-user-authenticator"

	ca, err := certauthority.New(pkix.Name{CommonName: serverName + " CA"}, time.Hour*24)
	require.NoError(t, err)

	cert, err := ca.Issue(pkix.Name{CommonName: serverName}, []string{serverName}, time.Hour*24)
	require.NoError(t, err)

	certPEM, keyPEM, err := certauthority.ToPEM(cert)
	require.NoError(t, err)

	certProvider := provider.NewDynamicTLSServingCertProvider()
	certProvider.Set(certPEM, keyPEM)

	return certProvider, ca.Bundle(), serverName
}

// newClient creates an http.Client that can be used to make an HTTPS call to a
// service whose serving certs can be verified by the provided CA bundle.
func newClient(caBundle []byte, serverName string) *http.Client {
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(caBundle)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    rootCAs,
				ServerName: serverName,
			},
		},
	}
}

// newTokenReviewBody creates an io.ReadCloser that contains a JSON-encoded
// TokenReview request.
func newTokenReviewBody(token string, extra ...string) (io.ReadCloser, error) {
	v := authenticationv1.SchemeGroupVersion.String()
	if len(extra) > 0 {
		v = extra[0]
	}

	k := "TokenReview"
	if len(extra) > 1 {
		k = extra[1]
	}

	buf := bytes.NewBuffer([]byte{})
	tr := authenticationv1.TokenReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v,
			Kind:       k,
		},
		Spec: authenticationv1.TokenReviewSpec{
			Token: token,
		},
	}
	err := json.NewEncoder(buf).Encode(&tr)
	return ioutil.NopCloser(buf), err
}

func unauthenticatedResponseJSON() *string {
	// Very specific expected result. Avoid using json package so we know exactly what we're asserting.
	s := `{
		"apiVersion": "authentication.k8s.io/v1beta1",
        "kind": "TokenReview",
		"status": {
			"authenticated": false
		}
	}`
	return &s
}

func authenticatedResponseJSON(user, uid string, groups []string) *string {
	quotedGroups := make([]string, len(groups))
	for i, group := range groups {
		quotedGroups[i] = `"` + group + `"`
	}

	// Very specific expected result. Avoid using json package so we know exactly what we're asserting.
	authenticatedJSONTemplate := `{
	  "apiVersion": "authentication.k8s.io/v1beta1",
	  "kind": "TokenReview",
	  "status": {
		"authenticated": true,
		"user": {
		  "username": "%s",
		  "uid": "%s",
		  "groups": [%s]
		}
	  }
	}`

	s := fmt.Sprintf(authenticatedJSONTemplate, user, uid, strings.Join(quotedGroups, ","))
	return &s
}

func addSecretToFakeClientTracker(t *testing.T, kubeClient *kubernetesfake.Clientset, username, uid, password, groups string) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			UID:       types.UID(uid),
			Name:      username,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"passwordHash": passwordHash,
			"groups":       []byte(groups),
		},
	}

	require.NoError(t, kubeClient.Tracker().Add(secret))
}
