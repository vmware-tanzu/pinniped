// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// +build !go1.14

package library

import (
	"context"
	"net"
)

// LookupIP looks up the IP address of the provided hostname, preferring IPv4.
func LookupIP(ctx context.Context, hostname string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip4", hostname)
}
