// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package client is a wrapper for interacting with Pinniped's CredentialRequest API.
package client

import (
	"context"
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/suzerain-io/pinniped/generated/1.19/apis/pinniped/v1alpha1"
	"github.com/suzerain-io/pinniped/generated/1.19/client/clientset/versioned"
)

// ErrLoginFailed is returned by ExchangeToken when the server rejects the login request.
var ErrLoginFailed = errors.New("login failed")

// ExchangeToken exchanges an opaque token using the Pinniped CredentialRequest API, returning a client-go ExecCredential valid on the target cluster.
func ExchangeToken(ctx context.Context, token string, caBundle string, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
	client, err := getClient(apiEndpoint, caBundle)
	if err != nil {
		return nil, fmt.Errorf("could not get API client: %w", err)
	}

	resp, err := client.PinnipedV1alpha1().CredentialRequests().Create(ctx, &v1alpha1.CredentialRequest{
		Spec: v1alpha1.CredentialRequestSpec{
			Type: v1alpha1.TokenCredentialType,
			Token: &v1alpha1.CredentialRequestTokenCredential{
				Value: token,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not login: %w", err)
	}
	if resp.Status.Credential == nil || resp.Status.Message != nil {
		return nil, fmt.Errorf("%w: %s", ErrLoginFailed, *resp.Status.Message)
	}

	return &clientauthenticationv1beta1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExecCredential",
			APIVersion: "client.authentication.k8s.io/v1beta1",
		},
		Status: &clientauthenticationv1beta1.ExecCredentialStatus{
			ExpirationTimestamp:   &resp.Status.Credential.ExpirationTimestamp,
			ClientCertificateData: resp.Status.Credential.ClientCertificateData,
			ClientKeyData:         resp.Status.Credential.ClientKeyData,
			Token:                 resp.Status.Credential.Token,
		},
	}, nil
}

// getClient returns an anonymous client for the Pinniped API at the provided endpoint/CA bundle.
func getClient(apiEndpoint string, caBundle string) (versioned.Interface, error) {
	cfg, err := clientcmd.NewNonInteractiveClientConfig(clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {
				Server:                   apiEndpoint,
				CertificateAuthorityData: []byte(caBundle),
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"current": {
				Cluster:  "cluster",
				AuthInfo: "client",
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"client": {},
		},
	}, "current", &clientcmd.ConfigOverrides{}, nil).ClientConfig()
	if err != nil {
		return nil, err
	}
	return versioned.NewForConfig(cfg)
}
