// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testlib

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/crypto/ptls"
)

func RunNmapSSLEnum(t *testing.T, host string, port uint16) (string, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	version, err := exec.CommandContext(ctx, "nmap", "-V").CombinedOutput()
	require.NoError(t, err)

	versionMatches := regexp.MustCompile(`Nmap version 7\.(?P<minor>\d+)`).FindStringSubmatch(string(version))
	require.Len(t, versionMatches, 2)
	minorVersion, err := strconv.Atoi(versionMatches[1])
	require.NoError(t, err)
	require.GreaterOrEqual(t, minorVersion, 92, "nmap >= 7.92.x is required")

	var stdout, stderr bytes.Buffer
	//nolint:gosec // we are not performing malicious argument injection against ourselves
	cmd := exec.CommandContext(ctx, "nmap", "--script", "ssl-enum-ciphers",
		"-p", strconv.FormatUint(uint64(port), 10),
		host,
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	require.NoErrorf(t, cmd.Run(), "stderr:\n%s\n\nstdout:\n%s\n\n", stderr.String(), stdout.String())

	return stdout.String(), stderr.String()
}

func GetExpectedCiphers(config *tls.Config) string {
	secureConfig := ptls.Secure(nil)

	skip12 := config.MinVersion == tls.VersionTLS13

	var tls12Bit, tls13Bit string

	if !skip12 {
		sort.SliceStable(config.CipherSuites, func(i, j int) bool {
			a := tls.CipherSuiteName(config.CipherSuites[i])
			b := tls.CipherSuiteName(config.CipherSuites[j])

			ok1 := strings.Contains(a, "_ECDSA_")
			ok2 := strings.Contains(b, "_ECDSA_")

			if ok1 && ok2 {
				return false
			}

			return ok1
		})

		var s strings.Builder
		for i, id := range config.CipherSuites {
			name := tls.CipherSuiteName(id)
			group := ""
			if strings.Contains(name, "_ECDHE_") {
				group = secp256r1
			} else {
				group = rsa2048
			}
			s.WriteString(fmt.Sprintf(tls12Item, name, group))
			if i == len(config.CipherSuites)-1 {
				break
			}
			s.WriteString("\n")
		}
		tls12Bit = fmt.Sprintf(tls12Base, s.String(), getCipherSuitePreference())
	}

	skip13 := config.MaxVersion == tls.VersionTLS12
	if !skip13 {
		var s strings.Builder
		for i, id := range secureConfig.CipherSuites {
			s.WriteString(fmt.Sprintf(tls13Item, strings.Replace(tls.CipherSuiteName(id), "TLS_", "TLS_AKE_WITH_", 1)))
			if i == len(secureConfig.CipherSuites)-1 {
				break
			}
			s.WriteString("\n")
		}
		tls13Bit = fmt.Sprintf(tls13Base, s.String())
	}

	return fmt.Sprintf(baseItem, tls12Bit, tls13Bit)
}

const (
	// this surrounds the tls 1.2 and 1.3 text in a way that guarantees that other TLS versions are not supported.
	baseItem = `/tcp open  unknown
| ssl-enum-ciphers: %s%s
|_  least strength: A

Nmap done: 1 IP address (1 host up) scanned in`

	// cipher preference is a variable because in FIPs mode it is server
	// but in normal mode it is client.
	tls12Base = `
|   TLSv1.2: 
|     ciphers: 
%s
|     compressors: 
|       NULL
|     cipher preference: %s`

	tls12Item = `|       %s (%s) - A`

	tls13Base = `
|   TLSv1.3: 
|     ciphers: 
%s
|     cipher preference: server`

	// This curve name is part of the output for each of our elliptic curve ciphers.
	// secp256r1 is also known as P-256.
	secp256r1 = "secp256r1"
	// For the RSA ciphers, we expect this output to be RSA 2048.
	rsa2048 = "rsa 2048"

	tls13Item = `|       %s (ecdh_x25519) - A`
)
