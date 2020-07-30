/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"time"
)

var (
	// ErrLoginFailed is returned by ExchangeToken when the server rejects the login request.
	ErrLoginFailed = fmt.Errorf("login failed")

	// ErrInvalidAPIEndpoint is returned by ExchangeToken when the provided API endpoint is invalid.
	ErrInvalidAPIEndpoint = fmt.Errorf("invalid API endpoint")

	// ErrInvalidCABundle is returned by ExchangeToken when the provided CA bundle is invalid.
	ErrInvalidCABundle = fmt.Errorf("invalid CA bundle")
)

const (
	// loginRequestsAPIPath is the API path for the v1alpha1 LoginRequest API.
	loginRequestsAPIPath = "/apis/placeholder.suzerain-io.github.io/v1alpha1/loginrequests"

	// userAgent is the user agent header value sent with requests.
	userAgent = "placeholder-name"
)

func loginRequest(ctx context.Context, apiEndpoint *url.URL, token string) (*http.Request, error) {
	type LoginRequestTokenCredential struct {
		Value string `json:"value"`
	}
	type LoginRequestSpec struct {
		Type  string                       `json:"type"`
		Token *LoginRequestTokenCredential `json:"token"`
	}
	body := struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			CreationTimestamp *string `json:"creationTimestamp"`
		} `json:"metadata"`
		Spec   LoginRequestSpec `json:"spec"`
		Status struct{}         `json:"status"`
	}{
		APIVersion: "placeholder.suzerain-io.github.io/v1alpha1",
		Kind:       "LoginRequest",
		Spec:       LoginRequestSpec{Type: "token", Token: &LoginRequestTokenCredential{Value: token}},
	}
	bodyJSON, err := json.Marshal(&body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiEndpoint.String(), bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	return req, nil
}

// Credential is the output of an ExchangeToken operation. It is equivalent to the data
// in the Kubernetes client.authentication.k8s.io/v1beta1 ExecCredentialStatus type.
type Credential struct {
	// ExpirationTimestamp indicates a time when the provided credentials expire.
	ExpirationTimestamp *time.Time

	// Token is a bearer token used by the client for request authentication.
	Token string

	// PEM-encoded client TLS certificates (including intermediates, if any).
	ClientCertificateData string

	// PEM-encoded private key for the above certificate.
	ClientKeyData string
}

func ExchangeToken(ctx context.Context, token, caBundle, apiEndpoint string) (*Credential, error) {
	// Parse and validate the provided API endpoint.
	endpointURL, err := url.Parse(apiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAPIEndpoint, err.Error())
	}
	if endpointURL.Scheme != "https" {
		return nil, fmt.Errorf(`%w: protocol must be "https", not %q`, ErrInvalidAPIEndpoint, endpointURL.Scheme)
	}

	// Form the LoginRequest API URL by appending the API path to the main API endpoint.
	placeholderEndpointURL := *endpointURL
	placeholderEndpointURL.Path = filepath.Join(placeholderEndpointURL.Path, loginRequestsAPIPath)

	// Initialize a TLS client configuration from the provided CA bundle.
	tlsConfig := tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    x509.NewCertPool(),
	}
	if !tlsConfig.RootCAs.AppendCertsFromPEM([]byte(caBundle)) {
		return nil, fmt.Errorf("%w: no certificates found", ErrInvalidCABundle)
	}

	// Create a request object for the "POST /apis/placeholder.suzerain-io.github.io/v1alpha1/loginrequests" request.
	req, err := loginRequest(ctx, &placeholderEndpointURL, token)
	if err != nil {
		return nil, fmt.Errorf("could not build request: %w", err)
	}

	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tlsConfig}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not login: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("could not login: server returned status %d", resp.StatusCode)
	}

	var respBody struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     struct {
			Credential *struct {
				ExpirationTimestamp   string `json:"expirationTimestamp"`
				Token                 string `json:"token"`
				ClientCertificateData string `json:"clientCertificateData"`
				ClientKeyData         string `json:"clientKeyData"`
			}
			Message string `json:"message"`
		} `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("invalid login response: %w", err)
	}

	if respBody.Status.Credential == nil || respBody.Status.Message != "" {
		return nil, fmt.Errorf("%w: %s", ErrLoginFailed, respBody.Status.Message)
	}

	result := Credential{
		Token:                 respBody.Status.Credential.Token,
		ClientCertificateData: respBody.Status.Credential.ClientCertificateData,
		ClientKeyData:         respBody.Status.Credential.ClientKeyData,
	}
	if str := respBody.Status.Credential.ExpirationTimestamp; str != "" {
		expiration, err := time.Parse(time.RFC3339, str)
		if err != nil {
			return nil, fmt.Errorf("invalid login response: %w", err)
		}
		result.ExpirationTimestamp = &expiration
	}

	return &result, nil
}
