package oidcclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

// RFC 8628 Device Authorization Response
type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
}

// OAuth2 Error Response
type oauth2ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// deviceCodeBasedAuth performs the RFC 8628 Device Authorization Grant flow.
func (h *handlerState) deviceCodeBasedAuth(_ *[]oauth2.AuthCodeOption) (*oidctypes.Token, error) {
	// Get the device authorization endpoint from the provider's discovery document.
	var claims struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	}
	if err := h.provider.Claims(&claims); err != nil || claims.DeviceAuthorizationEndpoint == "" {
		return nil, fmt.Errorf("issuer does not support device authorization grant (missing device_authorization_endpoint in discovery)")
	}

	// Send a request to the device authorization endpoint to get a device code and user code.
	reqBody := url.Values{}
	reqBody.Set("client_id", h.clientID)
	reqBody.Set("scope", strings.Join(h.scopes, " "))

	reqCtx, reqCancel := context.WithTimeout(h.ctx, httpRequestTimeout)
	defer reqCancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, claims.DeviceAuthorizationEndpoint, strings.NewReader(reqBody.Encode()))
	if err != nil {
		return nil, fmt.Errorf("could not build device authorization request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device authorization request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("device authorization endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var deviceResp deviceAuthorizationResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceResp); err != nil {
		return nil, fmt.Errorf("failed to decode device authorization response: %w", err)
	}

	interval := time.Duration(deviceResp.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	// Display the verification URL and user code to the user.
	displayURL := deviceResp.VerificationURI
	if deviceResp.VerificationURIComplete != "" {
		displayURL = deviceResp.VerificationURIComplete
	}

	fmt.Fprintf(h.out, "\nPlease visit the following URL to authenticate:\n")
	fmt.Fprintf(h.out, "  URL:  %s\n", displayURL)
	if deviceResp.VerificationURIComplete == "" {
		fmt.Fprintf(h.out, "  Code: %s\n", deviceResp.UserCode)
	}
	fmt.Fprintf(h.out, "\nWaiting for authentication...\n")

	// Poll the token endpoint for the access token and ID token.
	tokenEndpoint := h.oauth2Config.Endpoint.TokenURL
	pollTicker := time.NewTicker(interval)
	defer pollTicker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return nil, fmt.Errorf("timed out waiting for device authorization: %w", h.ctx.Err())

		case <-pollTicker.C:
			tokenReqBody := url.Values{}
			tokenReqBody.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
			tokenReqBody.Set("device_code", deviceResp.DeviceCode)
			tokenReqBody.Set("client_id", h.clientID)

			tokenCtx, tokenCancel := context.WithTimeout(h.ctx, httpRequestTimeout)
			tokenReq, err := http.NewRequestWithContext(tokenCtx, http.MethodPost, tokenEndpoint, strings.NewReader(tokenReqBody.Encode()))
			if err != nil {
				tokenCancel()
				return nil, fmt.Errorf("could not build token request: %w", err)
			}
			tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			tokenResp, err := h.httpClient.Do(tokenReq)
			tokenCancel()
			if err != nil {
				return nil, fmt.Errorf("token polling request failed: %w", err)
			}

			// Handle the token response based on the status code.
			if tokenResp.StatusCode == http.StatusOK {
				var rawToken struct {
					AccessToken  string `json:"access_token"`
					TokenType    string `json:"token_type"`
					RefreshToken string `json:"refresh_token"`
					IDToken      string `json:"id_token"`
					ExpiresIn    int    `json:"expires_in"`
				}
				err := json.NewDecoder(tokenResp.Body).Decode(&rawToken)
				tokenResp.Body.Close()
				if err != nil {
					return nil, fmt.Errorf("failed to decode token response: %w", err)
				}

				// Validate the ID token and extract claims.
				verifiedIDToken, err := h.validateIDToken(h.ctx, h.provider, h.clientID, rawToken.IDToken)
				if err != nil {
					return nil, fmt.Errorf("failed to validate ID token: %w", err)
				}

				// Extract claims from the verified ID token.
				var claims map[string]any
				if err := verifiedIDToken.Claims(&claims); err != nil {
					return nil, fmt.Errorf("failed to extract claims from ID token: %w", err)
				}

				token := &oidctypes.Token{
					AccessToken: &oidctypes.AccessToken{
						Token: rawToken.AccessToken,
					},
					IDToken: &oidctypes.IDToken{
						Token:  rawToken.IDToken,
						Claims: claims,
						Expiry: metav1.NewTime(verifiedIDToken.Expiry),
					},
				}
				if rawToken.RefreshToken != "" {
					token.RefreshToken = &oidctypes.RefreshToken{
						Token: rawToken.RefreshToken,
					}
				}

				return token, nil
			}

			// Handle error responses from the token endpoint.
			var errResp oauth2ErrorResponse
			_ = json.NewDecoder(tokenResp.Body).Decode(&errResp)
			tokenResp.Body.Close()

			switch errResp.Error {
			case "authorization_pending":
				continue

			case "slow_down":
				interval += 5 * time.Second
				pollTicker.Reset(interval)
				continue

			case "expired_token":
				return nil, fmt.Errorf("device code has expired, please try logging in again")

			case "access_denied":
				return nil, fmt.Errorf("login access was denied by the user")

			default:
				if errResp.ErrorDescription != "" {
					return nil, fmt.Errorf("login failed: %s (%s)", errResp.Error, errResp.ErrorDescription)
				}
				return nil, fmt.Errorf("login failed with error: %s", errResp.Error)
			}
		}
	}
}
