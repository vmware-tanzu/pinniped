// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testlib

import (
	"context"
	"net"
)

// LookupIP looks up the IP address of the provided hostname, preferring IPv4.
func LookupIP(ctx context.Context, hostname string) ([]net.IP, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, err
	}

	// Filter out to only IPv4 addresses
	var results []net.IP
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			results = append(results, ip.IP)
		}
	}
	return results, nil
}
