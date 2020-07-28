/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	placeholderclientset "github.com/suzerain-io/placeholder-name-client-go/pkg/generated/clientset/versioned"
	"github.com/suzerain-io/placeholder-name/internal/constable"
)

// ErrLoginFailed is returned by ExchangeToken when the server rejects the login request.
const ErrLoginFailed = constable.Error("login failed")

func ExchangeToken(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthentication.ExecCredential, error) {
	clientset, err := getClient(apiEndpoint, caBundle)
	if err != nil {
		return nil, fmt.Errorf("could not get API client: %w", err)
	}

	resp, err := clientset.PlaceholderV1alpha1().LoginRequests().Create(ctx, &placeholderv1alpha1.LoginRequest{
		Spec: placeholderv1alpha1.LoginRequestSpec{
			Type: placeholderv1alpha1.TokenLoginCredentialType,
			Token: &placeholderv1alpha1.LoginRequestTokenCredential{
				Value: token,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not login: %w", err)
	}
	if resp.Status.Credential == nil || resp.Status.Message != "" {
		return nil, fmt.Errorf("%w: %s", ErrLoginFailed, resp.Status.Message)
	}

	return &clientauthentication.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExecCredential",
			APIVersion: "client.authentication.k8s.io/v1beta1",
		},
		Status: &clientauthentication.ExecCredentialStatus{
			ExpirationTimestamp:   resp.Status.Credential.ExpirationTimestamp,
			ClientCertificateData: resp.Status.Credential.ClientCertificateData,
			ClientKeyData:         resp.Status.Credential.ClientKeyData,
		},
	}, nil
}

// getClient returns an anonymous clientset for the placeholder-name API at the provided endpoint/CA bundle.
func getClient(apiEndpoint string, caBundle string) (placeholderclientset.Interface, error) {
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
	}, "current", nil, nil).ClientConfig()
	if err != nil {
		return nil, err
	}
	return placeholderclientset.NewForConfig(cfg)
}
