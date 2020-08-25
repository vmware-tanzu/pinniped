/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"github.com/suzerain-io/pinniped/internal/client"
	"github.com/suzerain-io/pinniped/internal/constable"
)

func main() {
	err := run(os.LookupEnv, client.ExchangeToken, os.Stdout, 30*time.Second)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}

type envGetter func(string) (string, bool)
type tokenExchanger func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error)

const ErrMissingEnvVar = constable.Error("failed to get credential: environment variable not set")

func run(envGetter envGetter, tokenExchanger tokenExchanger, outputWriter io.Writer, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	token, varExists := envGetter("PINNIPED_TOKEN")
	if !varExists {
		return envVarNotSetError("PINNIPED_TOKEN")
	}

	caBundle, varExists := envGetter("PINNIPED_CA_BUNDLE")
	if !varExists {
		return envVarNotSetError("PINNIPED_CA_BUNDLE")
	}

	apiEndpoint, varExists := envGetter("PINNIPED_K8S_API_ENDPOINT")
	if !varExists {
		return envVarNotSetError("PINNIPED_K8S_API_ENDPOINT")
	}

	cred, err := tokenExchanger(ctx, token, caBundle, apiEndpoint)
	if err != nil {
		return fmt.Errorf("failed to get credential: %w", err)
	}

	err = json.NewEncoder(outputWriter).Encode(cred)
	if err != nil {
		return fmt.Errorf("failed to marshal response to stdout: %w", err)
	}

	return nil
}

func envVarNotSetError(varName string) error {
	return fmt.Errorf("%w: %s", ErrMissingEnvVar, varName)
}
