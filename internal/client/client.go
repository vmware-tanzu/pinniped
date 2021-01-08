// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package client is a wrapper for interacting with Pinniped's CredentialRequest API.
package client

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"go.pinniped.dev/generated/1.19/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned"
	"go.pinniped.dev/internal/kubeclient"
)

// ErrLoginFailed is returned by ExchangeToken when the server rejects the login request.
var ErrLoginFailed = errors.New("login failed")

// ExchangeToken exchanges an opaque token using the Pinniped TokenCredentialRequest API, returning a client-go ExecCredential valid on the target cluster.
func ExchangeToken(ctx context.Context, namespace string, authenticator corev1.TypedLocalObjectReference, token string, caBundle string, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error) {
	client, err := getClient(apiEndpoint, caBundle)
	if err != nil {
		return nil, fmt.Errorf("could not get API client: %w", err)
	}

	resp, err := client.LoginV1alpha1().TokenCredentialRequests(namespace).Create(ctx, &v1alpha1.TokenCredentialRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
		},
		Spec: v1alpha1.TokenCredentialRequestSpec{
			Token:         token,
			Authenticator: authenticator,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not login: %w", err)
	}
	if resp.Status.Credential == nil || resp.Status.Message != nil {
		if resp.Status.Message != nil {
			return nil, fmt.Errorf("%w: %s", ErrLoginFailed, *resp.Status.Message)
		}
		return nil, fmt.Errorf("%w: unknown", ErrLoginFailed)
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
	client, err := kubeclient.New(kubeclient.WithConfig(cfg))
	if err != nil {
		return nil, err
	}
	return client.PinnipedConcierge, nil
}
