// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package main is the combined entrypoint for the Pinniped "kube-cert-agent" component.
package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math"
	"os"
	"time"

	// this side effect import ensures that we use fipsonly crypto in fips_strict mode.
	_ "go.pinniped.dev/internal/crypto/ptls"
)

//nolint:gochecknoglobals // these are swapped during unit tests.
var (
	getenv = os.Getenv
	fail   = log.Fatalf
	sleep  = time.Sleep
	out    = io.Writer(os.Stdout)
)

func main() {
	if len(os.Args) < 2 {
		fail("missing subcommand")
	}

	switch os.Args[1] {
	case "sleep":
		sleep(math.MaxInt64)
	case "print":
		certBytes, err := os.ReadFile(getenv("CERT_PATH"))
		if err != nil {
			fail("could not read CERT_PATH: %v", err)
		}
		keyBytes, err := os.ReadFile(getenv("KEY_PATH"))
		if err != nil {
			fail("could not read KEY_PATH: %v", err)
		}
		if err := json.NewEncoder(out).Encode(&struct {
			Cert string `json:"tls.crt"`
			Key  string `json:"tls.key"`
		}{
			Cert: base64.StdEncoding.EncodeToString(certBytes),
			Key:  base64.StdEncoding.EncodeToString(keyBytes),
		}); err != nil {
			fail("failed to write output: %v", err)
		}
	default:
		fail("invalid subcommand %q", os.Args[1])
	}
}
