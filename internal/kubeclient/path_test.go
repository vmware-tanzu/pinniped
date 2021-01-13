// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/1.20/apis/supervisor/config/v1alpha1"
)

func Test_updatePathNewGVK(t *testing.T) {
	type args struct {
		reqURL        *url.URL
		result        *mutationResult
		apiPathPrefix string
		reqInfo       *genericapirequest.RequestInfo
	}
	tests := []struct {
		name    string
		args    args
		want    *url.URL
		wantErr bool
	}{
		{
			name: "no gvk change",
			args: args{
				reqURL: mustParse(t, "https://walrus.tld/api/v1/pods"),
				result: &mutationResult{},
			},
			want: mustParse(t, "https://walrus.tld/api/v1/pods"),
		},
		{
			name: "no original gvk group",
			args: args{
				result: &mutationResult{
					origGVK: schema.GroupVersionKind{
						Group: "",
					},
					gvkChanged: true,
				},
			},
			wantErr: true,
		},
		{
			name: "cluster-scoped list path",
			args: args{
				reqURL: mustParse(t, "https://walrus.tld/apis/"+loginv1alpha1.SchemeGroupVersion.String()+"/tokencredentialrequests"),
				result: &mutationResult{
					origGVK: loginv1alpha1.SchemeGroupVersion.WithKind("TokenCredentialRequest"),
					newGVK: schema.GroupVersionKind{
						Group:   "login.concierge.tuna.io",
						Version: loginv1alpha1.SchemeGroupVersion.Version,
						Kind:    "TokenCredentialRequest",
					},
					gvkChanged: true,
				},
				apiPathPrefix: "/apis",
				reqInfo:       &genericapirequest.RequestInfo{},
			},
			want: mustParse(t, "https://walrus.tld/apis/login.concierge.tuna.io/v1alpha1/tokencredentialrequests"),
		},
		{
			name: "cluster-scoped get path",
			args: args{
				reqURL: mustParse(t, "https://walrus.tld/apis/"+loginv1alpha1.SchemeGroupVersion.String()+"/tokencredentialrequests/some-name"),
				result: &mutationResult{
					origGVK: loginv1alpha1.SchemeGroupVersion.WithKind("TokenCredentialRequest"),
					newGVK: schema.GroupVersionKind{
						Group:   "login.concierge.tuna.io",
						Version: loginv1alpha1.SchemeGroupVersion.Version,
						Kind:    "TokenCredentialRequest",
					},
					gvkChanged: true,
				},
				apiPathPrefix: "/apis",
				reqInfo:       &genericapirequest.RequestInfo{},
			},
			want: mustParse(t, "https://walrus.tld/apis/login.concierge.tuna.io/v1alpha1/tokencredentialrequests/some-name"),
		},
		{
			name: "namespace-scoped list path",
			args: args{
				reqURL: mustParse(t, "https://walrus.tld/apis/"+configv1alpha1.SchemeGroupVersion.String()+"/namespaces/default/federationdomains"),
				result: &mutationResult{
					origGVK: configv1alpha1.SchemeGroupVersion.WithKind("FederationDomain"),
					newGVK: schema.GroupVersionKind{
						Group:   "config.supervisor.tuna.io",
						Version: configv1alpha1.SchemeGroupVersion.Version,
						Kind:    "FederationDomain",
					},
					gvkChanged: true,
				},
				apiPathPrefix: "/apis",
				reqInfo:       &genericapirequest.RequestInfo{},
			},
			want: mustParse(t, "https://walrus.tld/apis/config.supervisor.tuna.io/v1alpha1/namespaces/default/federationdomains"),
		},
		{
			name: "namespace-scoped get path",
			args: args{
				reqURL: mustParse(t, "https://walrus.tld/apis/"+configv1alpha1.SchemeGroupVersion.String()+"/namespaces/default/federationdomains/some-name"),
				result: &mutationResult{
					origGVK: configv1alpha1.SchemeGroupVersion.WithKind("FederationDomain"),
					newGVK: schema.GroupVersionKind{
						Group:   "config.supervisor.tuna.io",
						Version: configv1alpha1.SchemeGroupVersion.Version,
						Kind:    "FederationDomain",
					},
					gvkChanged: true,
				},
				apiPathPrefix: "/apis",
				reqInfo:       &genericapirequest.RequestInfo{},
			},
			want: mustParse(t, "https://walrus.tld/apis/config.supervisor.tuna.io/v1alpha1/namespaces/default/federationdomains/some-name"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := updatePathNewGVK(tt.args.reqURL, tt.args.result, tt.args.apiPathPrefix, tt.args.reqInfo)
			if (err != nil) != tt.wantErr {
				t.Errorf("updatePathNewGVK() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("updatePathNewGVK() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_reqWithoutPrefix(t *testing.T) {
	body := ioutil.NopCloser(bytes.NewBuffer([]byte("some body")))
	newReq := func(rawurl string) *http.Request {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawurl, body)
		require.NoError(t, err)
		return req
	}

	type args struct {
		req           *http.Request
		hostURL       string
		apiPathPrefix string
	}
	tests := []struct {
		name string
		args args
		want *http.Request
	}{
		{
			name: "happy path",
			args: args{
				req:           newReq("https://walrus.tld/apis/some/path"),
				hostURL:       "https://walrus.tld",
				apiPathPrefix: "/apis",
			},
			want: newReq("https://walrus.tld/some/path"),
		},
		{
			name: "host url already has slash suffix",
			args: args{
				req:           newReq("https://walrus.tld/apis/some/path"),
				hostURL:       "https://walrus.tld/",
				apiPathPrefix: "/apis",
			},
			want: newReq("https://walrus.tld/some/path"),
		},
		{
			name: "api prefix already has slash prefix",
			args: args{
				req:           newReq("https://walrus.tld/apis/some/path"),
				hostURL:       "https://walrus.tld",
				apiPathPrefix: "apis",
			},
			want: newReq("https://walrus.tld/some/path"),
		},
		{
			name: "api prefix already has slash suffix",
			args: args{
				req:           newReq("https://walrus.tld/apis/some/path"),
				hostURL:       "https://walrus.tld",
				apiPathPrefix: "/apis/",
			},
			want: newReq("https://walrus.tld/some/path"),
		},
		{
			name: "no api path prefix",
			args: args{
				req: newReq("https://walrus.tld"),
			},
			want: newReq("https://walrus.tld"),
		},
		{
			name: "hostURL and req URL mismatch",
			args: args{
				req:           newReq("https://walrus.tld.some-other-url/some/path"),
				hostURL:       "https://walrus.tld",
				apiPathPrefix: "/apis",
			},
			want: newReq("https://walrus.tld.some-other-url/some/path"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			req := *tt.args.req
			if got := reqWithoutPrefix(&req, tt.args.hostURL, tt.args.apiPathPrefix); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("reqWithoutPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func mustParse(t *testing.T, rawurl string) *url.URL {
	t.Helper()
	url, err := url.Parse(rawurl)
	require.NoError(t, err)
	return url
}
