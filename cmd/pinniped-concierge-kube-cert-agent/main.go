// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
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

	// This side effect import ensures that we use fipsonly crypto in boringcrypto mode.
	// Commenting this out because it causes the runtime memory consumption of this binary to increase
	// from ~1 MB to ~8 MB (as measured when running the sleep subcommand). This binary does not use TLS,
	// so it should not be needed. If this binary is ever changed to make use of TLS client and/or server
	// code, then we should bring this import back to support the use of the ptls library for client and
	// server code, and we should also increase the memory limits on the kube cert agent deployment (as
	// decided by the kube cert agent controller in the Concierge).
	//
	//nolint:godot // This is not sentence, it is a commented out line of import code.
	//_ "go.pinniped.dev/internal/crypto/ptls"

	// This side effect ensures building with at least go1.19
	_ "go.pinniped.dev/internal/build"
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
