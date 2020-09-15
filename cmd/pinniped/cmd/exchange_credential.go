/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"github.com/suzerain-io/pinniped/internal/client"
	"github.com/suzerain-io/pinniped/internal/constable"
	"github.com/suzerain-io/pinniped/internal/here"
)

//nolint: gochecknoinits
func init() {
	rootCmd.AddCommand(newExchangeCredentialCmd(os.Args, os.Stdout, os.Stderr).cmd)
}

type exchangeCredentialCommand struct {
	// runFunc is called by the cobra.Command.Run hook. It is included here for
	// testability.
	runFunc func(stdout, stderr io.Writer)

	// cmd is the cobra.Command for this CLI command. It is included here for
	// testability.
	cmd *cobra.Command
}

func newExchangeCredentialCmd(args []string, stdout, stderr io.Writer) *exchangeCredentialCommand {
	c := &exchangeCredentialCommand{
		runFunc: runExchangeCredential,
	}

	c.cmd = &cobra.Command{
		Run: func(cmd *cobra.Command, _ []string) {
			c.runFunc(stdout, stderr)
		},
		Args:  cobra.NoArgs, // do not accept positional arguments for this command
		Use:   "exchange-credential",
		Short: "Exchange a credential for a cluster-specific access credential",
		Long: here.Doc(`
			Exchange a credential which proves your identity for a time-limited,
			cluster-specific access credential.

			Designed to be conveniently used as an credential plugin for kubectl.
			See the help message for 'pinniped get-kubeconfig' for more
			information about setting up a kubeconfig file using Pinniped.

			Requires all of the following environment variables, which are
			typically set in the kubeconfig:
			  - PINNIPED_TOKEN: the token to send to Pinniped for exchange
			  - PINNIPED_CA_BUNDLE: the CA bundle to trust when calling
				Pinniped's HTTPS endpoint
			  - PINNIPED_K8S_API_ENDPOINT: the URL for the Pinniped credential
				exchange API

			For more information about credential plugins in general, see
			https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins
		`),
	}

	c.cmd.SetArgs(args)
	c.cmd.SetOut(stdout)
	c.cmd.SetErr(stderr)

	return c
}

type envGetter func(string) (string, bool)
type tokenExchanger func(ctx context.Context, token, caBundle, apiEndpoint string) (*clientauthenticationv1beta1.ExecCredential, error)

const ErrMissingEnvVar = constable.Error("failed to get credential: environment variable not set")

func runExchangeCredential(stdout, _ io.Writer) {
	err := exchangeCredential(os.LookupEnv, client.ExchangeToken, stdout, 30*time.Second)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}

func exchangeCredential(envGetter envGetter, tokenExchanger tokenExchanger, outputWriter io.Writer, timeout time.Duration) error {
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
