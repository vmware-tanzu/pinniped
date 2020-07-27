/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package client

import "k8s.io/client-go/pkg/apis/clientauthentication"

func ExchangeToken(token, caBundle, apiEndpoint string) (*clientauthentication.ExecCredential, error) {
	_ = token
	_ = caBundle
	_ = apiEndpoint
	return nil, nil
}
