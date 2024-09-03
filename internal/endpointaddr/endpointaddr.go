// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package endpointaddr implements parsing and validation of "<host>[:<port>]" strings for Pinniped APIs.
package endpointaddr

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type HostPort struct {
	// Host is the validated host part of the input, which may be a hostname or IP.
	//
	// This string can be used as a x509 certificate SAN.
	Host string

	// Port is the validated port number, which may be defaulted.
	Port uint16
}

// Endpoint is the host:port validated from the input, where port may be a default value.
//
// This string can be passed to net.Dial.
func (h *HostPort) Endpoint() string {
	return net.JoinHostPort(h.Host, strconv.Itoa(int(h.Port)))
}

// Parse an "endpoint address" string, providing a default port. The input can be in several valid formats:
//
// - "<hostname>"        (DNS hostname)
// - "<IPv4>"            (IPv4 address)
// - "<IPv6>"            (IPv6 address)
// - "<hostname>:<port>" (DNS hostname with port)
// - "<IPv4>:<port>"     (IPv4 address with port)
// - "[<IPv6>]:<port>"   (IPv6 address with port, brackets are required)
//
// If the input does not specify a port number, then defaultPort will be used.
func Parse(endpoint string, defaultPort uint16) (HostPort, error) {
	// Try parsing it both with and without an implicit port 443 at the end.
	host, port, err := net.SplitHostPort(endpoint)

	// If we got an error parsing the raw input, try adding the default port.
	if err != nil {
		host, port, err = net.SplitHostPort(net.JoinHostPort(endpoint, strconv.Itoa(int(defaultPort))))
	}

	// Give up if there's still an error splitting the host and port.
	if err != nil {
		return HostPort{}, err
	}

	// Parse the port number is an integer in the range of valid ports.
	integerPort, _ := strconv.Atoi(port)
	if len(validation.IsValidPortNum(integerPort)) > 0 {
		return HostPort{}, fmt.Errorf("invalid port %q", port)
	}

	// Check if the host part is a IPv4 or IPv6 address or a valid hostname according to RFC 1123.
	switch {
	case len(validation.IsValidIP(field.NewPath("UNKNOWN_PATH"), host)) == 0:
	// The host name should be case-insensitive.
	case len(validation.IsDNS1123Subdomain(strings.ToLower(host))) == 0:
	default:
		return HostPort{}, fmt.Errorf("host %q is not a valid hostname or IP address", host)
	}

	return HostPort{
		Host: host,
		Port: uint16(integerPort), //nolint:gosec // this cast is checked by validation.IsValidPortNum above
	}, nil
}

// ParseFromURL wraps Parse but specifically takes a url.URL instead of an endpoint string.
// ParseFromURL differs from Parse in that IPv6 addresses must be wrapped in brackets
// when used in a URL (even when used without a port).
//
// If the input does not specify a port number, then defaultPort will be used.
//
// The RFC for literal IPv6 addresses in URLs indicates that brackets
// - must be used when a port is provided
// - should be used when a port is not provided, but does not indicate "must"
// See https://datatracker.ietf.org/doc/html/rfc2732#section-2
//
// However, the Golang docs make it clear that IPv6 addresses must be wrapped
// in brackets when used in a URL.
// See https://pkg.go.dev/net/url#URL
//
// Note that ParseFromURL returns a HostPort which has an Endpoint() method which
// will return a properly constructed URL with brackets when appropriate.
func ParseFromURL(u *url.URL, defaultPort uint16) (HostPort, error) {
	host := u.Host
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	return Parse(host, defaultPort)
}
