// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package downstreamsubject

import (
	"fmt"
	"net/url"

	"go.pinniped.dev/generated/latest/apis/supervisor/oidc"
)

func LDAP(uid string, ldapURL url.URL, idpDisplayName string) string {
	q := ldapURL.Query()
	q.Set(oidc.IDTokenSubClaimIDPNameQueryParam, idpDisplayName)
	q.Set(oidc.IDTokenClaimSubject, uid)
	ldapURL.RawQuery = q.Encode()
	return ldapURL.String()
}

func OIDC(upstreamIssuerAsString string, upstreamSubject string, idpDisplayName string) string {
	return fmt.Sprintf("%s?%s=%s&%s=%s", upstreamIssuerAsString,
		oidc.IDTokenSubClaimIDPNameQueryParam, url.QueryEscape(idpDisplayName),
		oidc.IDTokenClaimSubject, url.QueryEscape(upstreamSubject),
	)
}

func GitHub(apiBaseURL, idpDisplayName, login, id string) string {
	return fmt.Sprintf("%s?%s=%s&login=%s&id=%s", apiBaseURL,
		oidc.IDTokenSubClaimIDPNameQueryParam, url.QueryEscape(idpDisplayName),
		url.QueryEscape(login),
		url.QueryEscape(id),
	)
}
