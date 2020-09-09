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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	uid, otherUID, colonUID := "some-uid", "some-other-uid", "some-colon-uid"
	user, otherUser, colonUser := "some-user", "some-other-user", "some-colon-user"
	password, otherPassword, colonPassword := "some-password", "some-other-password", "some-:-password"
	group0, group1 := "some-group-0", "some-group-1"

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)

	otherPasswordHash, err := bcrypt.GenerateFromPassword([]byte(otherPassword), bcrypt.MinCost)
	require.NoError(t, err)

	colonPasswordHash, err := bcrypt.GenerateFromPassword([]byte(colonPassword), bcrypt.MinCost)
	require.NoError(t, err)

	groups := group0 + " , " + group1

	userSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			UID:       types.UID(uid),
			Name:      user,
			Namespace: "test-webhook",
		},
		Data: map[string][]byte{
			"passwordHash": passwordHash,
			"groups":       []byte(groups),
		},
	}
	otherUserSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			UID:       types.UID(otherUID),
			Name:      otherUser,
			Namespace: "test-webhook",
		},
		Data: map[string][]byte{
			"passwordHash": otherPasswordHash,
			"groups":       []byte(groups),
		},
	}
	colonUserSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			UID:       types.UID(colonUID),
			Name:      colonUser,
			Namespace: "test-webhook",
		},
		Data: map[string][]byte{
			"passwordHash": colonPasswordHash,
			"groups":       []byte(groups),
		},
	}

	kubeClient := kubernetesfake.NewSimpleClientset()
	require.NoError(t, kubeClient.Tracker().Add(userSecret))
	require.NoError(t, kubeClient.Tracker().Add(otherUserSecret))
	require.NoError(t, kubeClient.Tracker().Add(colonUserSecret))

	secretInformer := createSecretInformer(t, kubeClient)

	certProvider, caBundle, serverName := newCertProvider(t)
	w := newWebhook(certProvider, secretInformer)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	require.NoError(t, w.start(ctx, l))

	client := newClient(caBundle, serverName)

	tests := []struct {
		name    string
		url     string
		method  string
		headers map[string][]string
		body    func() (io.ReadCloser, error)

		wantStatus  int
		wantHeaders map[string][]string
		wantBody    *authenticationv1.TokenReview
	}{
		{
			name:   "success",
			url:    fmt.Sprintf("https://%s/authenticate", l.Addr().String()),
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			},
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody(user + ":" + password)
			},
			wantStatus: http.StatusOK,
			wantHeaders: map[string][]string{
				"Content-Type": []string{"application/json"},
			},
			wantBody: &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					User: authenticationv1.UserInfo{
						Username: user,
						UID:      uid,
						Groups:   []string{group0, group1},
					},
				},
			},
		},
		{
			name:   "wrong username for password",
			url:    fmt.Sprintf("https://%s/authenticate", l.Addr().String()),
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			},
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody(otherUser + ":" + password)
			},
			wantStatus: http.StatusOK,
			wantHeaders: map[string][]string{
				"Content-Type": []string{"application/json"},
			},
			wantBody: &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: false,
				},
			},
		},
		{
			name:   "wrong password for username",
			url:    fmt.Sprintf("https://%s/authenticate", l.Addr().String()),
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			},
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody(user + ":" + otherPassword)
			},
			wantStatus: http.StatusOK,
			wantHeaders: map[string][]string{
				"Content-Type": []string{"application/json"},
			},
			wantBody: &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: false,
				},
			},
		},
		{
			name:   "non-existent password for username",
			url:    fmt.Sprintf("https://%s/authenticate", l.Addr().String()),
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			},
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody(user + ":" + "some-non-existent-password")
			},
			wantStatus: http.StatusOK,
			wantHeaders: map[string][]string{
				"Content-Type": []string{"application/json"},
			},
			wantBody: &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: false,
				},
			},
		},
		{
			name:   "non-existent username",
			url:    fmt.Sprintf("https://%s/authenticate", l.Addr().String()),
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			},
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody("some-non-existent-user" + ":" + password)
			},
			wantStatus: http.StatusOK,
			wantHeaders: map[string][]string{
				"Content-Type": []string{"application/json"},
			},
			wantBody: &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: false,
				},
			},
		},
		{
			name:   "invalid token (missing colon)",
			url:    fmt.Sprintf("https://%s/authenticate", l.Addr().String()),
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			},
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody(user)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "password contains colon",
			url:    fmt.Sprintf("https://%s/authenticate", l.Addr().String()),
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			},
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody(colonUser + ":" + colonPassword)
			},
			wantStatus: http.StatusOK,
			wantHeaders: map[string][]string{
				"Content-Type": []string{"application/json"},
			},
			wantBody: &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					User: authenticationv1.UserInfo{
						Username: colonUser,
						UID:      colonUID,
						Groups:   []string{group0, group1},
					},
				},
			},
		},
		{
			name:   "bad path",
			url:    fmt.Sprintf("https://%s/tuna", l.Addr().String()),
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			},
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody("some-token")
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name:   "bad method",
			url:    fmt.Sprintf("https://%s/authenticate", l.Addr().String()),
			method: http.MethodGet,
			headers: map[string][]string{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			},
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody("some-token")
			},
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:   "bad content type",
			url:    fmt.Sprintf("https://%s/authenticate", l.Addr().String()),
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": []string{"application/xml"},
				"Accept":       []string{"application/json"},
			},
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody("some-token")
			},
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:   "bad accept",
			url:    fmt.Sprintf("https://%s/authenticate", l.Addr().String()),
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/xml"},
			},
			body: func() (io.ReadCloser, error) {
				return newTokenReviewBody("some-token")
			},
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:   "bad body",
			url:    fmt.Sprintf("https://%s/authenticate", l.Addr().String()),
			method: http.MethodPost,
			headers: map[string][]string{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			},
			body: func() (io.ReadCloser, error) {
				return ioutil.NopCloser(bytes.NewBuffer([]byte("invalid body"))), nil
			},
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			url, err := url.Parse(test.url)
			require.NoError(t, err)

			body, err := test.body()
			require.NoError(t, err)

			rsp, err := client.Do(&http.Request{
				Method: test.method,
				URL:    url,
				Header: test.headers,
				Body:   body,
			})
			require.NoError(t, err)
			defer rsp.Body.Close()

			if test.wantStatus != 0 {
				require.Equal(t, test.wantStatus, rsp.StatusCode)
			}
			if test.wantHeaders != nil {
				for k, v := range test.wantHeaders {
					require.Equal(t, v, rsp.Header.Values(k))
				}
			}
			if test.wantBody != nil {
				rspBody, err := newTokenReview(rsp.Body)
				require.NoError(t, err)
				require.Equal(t, test.wantBody, rspBody)
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

	ca, err := certauthority.New(pkix.Name{CommonName: "test-webhook CA"}, time.Hour*24)
	require.NoError(t, err)

	serverName := "test-webhook"
	cert, err := ca.Issue(
		pkix.Name{CommonName: serverName},
		[]string{},
		time.Hour*24,
	)
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
func newTokenReviewBody(token string) (io.ReadCloser, error) {
	buf := bytes.NewBuffer([]byte{})
	tr := authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token: token,
		},
	}
	err := json.NewEncoder(buf).Encode(&tr)
	return ioutil.NopCloser(buf), err
}

// newTokenReview reads a JSON-encoded authenticationv1.TokenReview from an
// io.Reader.
func newTokenReview(body io.Reader) (*authenticationv1.TokenReview, error) {
	var tr authenticationv1.TokenReview
	err := json.NewDecoder(body).Decode(&tr)
	return &tr, err
}
