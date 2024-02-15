// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package loginurl

import (
	"net/url"

	"go.pinniped.dev/internal/federationdomain/oidc"
)

const (
	UsernameParamName = "username"
	PasswordParamName = "password"
	StateParamName    = "state"
	ErrParamName      = "err"

	ShowNoError        ErrorParamValue = ""
	ShowInternalError  ErrorParamValue = "internal_error"
	ShowBadUserPassErr ErrorParamValue = "login_error"
)

type ErrorParamValue string

// URL returns the URL for the GET /login page of the specified issuer.
// The specified issuer should never end with a "/", which is validated by
// provider.FederationDomainIssuer when the issuer string comes from that type.
func URL(
	downstreamIssuer string,
	encodedStateParamValue string,
	errToDisplay ErrorParamValue,
) (string, error) {
	loginURL, err := url.Parse(downstreamIssuer + oidc.PinnipedLoginPath)
	if err != nil {
		return "", err
	}

	q := loginURL.Query()
	q.Set(StateParamName, encodedStateParamValue)
	if errToDisplay != ShowNoError {
		q.Set(ErrParamName, string(errToDisplay))
	}
	loginURL.RawQuery = q.Encode()

	return loginURL.String(), nil
}
