/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"k8s.io/client-go/pkg/apis/clientauthentication"

	"github.com/suzerain-io/placeholder-name/internal/constable"
	"github.com/suzerain-io/placeholder-name/pkg/client"
)

func main() {
	err := run(os.LookupEnv, client.ExchangeToken, os.Stdout)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s", err.Error())
		os.Exit(1)
	}
}

type envGetter func(string) (string, bool)
type tokenExchanger func(token, caBundle, apiEndpoint string) (*clientauthentication.ExecCredential, error)

const ErrMissingEnvVar = constable.Error("failed to login: environment variable not set")

func run(envGetter envGetter, tokenExchanger tokenExchanger, outputWriter io.Writer) error {
	token, varExists := envGetter("PLACEHOLDER_NAME_TOKEN")
	if !varExists {
		return envVarNotSetError("PLACEHOLDER_NAME_TOKEN")
	}

	caBundle, varExists := envGetter("PLACEHOLDER_NAME_CA_BUNDLE")
	if !varExists {
		return envVarNotSetError("PLACEHOLDER_NAME_CA_BUNDLE")
	}

	apiEndpoint, varExists := envGetter("PLACEHOLDER_NAME_K8S_API_ENDPOINT")
	if !varExists {
		return envVarNotSetError("PLACEHOLDER_NAME_K8S_API_ENDPOINT")
	}

	execCredential, err := tokenExchanger(token, caBundle, apiEndpoint)
	if err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}

	err = json.NewEncoder(outputWriter).Encode(execCredential)
	if err != nil {
		return fmt.Errorf("failed to marshall response to stdout: %w", err)
	}

	return nil
}

func envVarNotSetError(varName string) error {
	return fmt.Errorf("%w: %s", ErrMissingEnvVar, varName)
}
