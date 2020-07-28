/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"context"

	"k8s.io/client-go/pkg/apis/clientauthentication"
)

func ExchangeToken(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthentication.ExecCredential, error) {
	_, _, _, _ = ctx, token, caBundle, apiEndpoint
	return nil, nil
}
