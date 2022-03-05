// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"

	"go.pinniped.dev/internal/plog"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"

	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/filesession"
)

//nolint: gochecknoinits
func init() {
	rootCmd.AddCommand(newLogoutCommand())
}

type logoutFlags struct {
	kubeconfigPath            string
	kubeconfigContextOverride string
}

// This implements client side logout-- i.e. deleting the cached tokens and certificates for a user
// without telling the supervisor to forget about the users tokens. From a user experience
// perspective these are identical, but it leaves orphaned tokens lying around that the supervisor
// won't garbage collect for up to 9 hours.
// Fosite supports token revocation requests ala https://tools.ietf.org/html/rfc7009#section-2.1
// with their TokenRevocationHandler, but we would also want to turn around and revoke the upstream
// tokens in the case of OIDC.
// That's something that could be done to improve security and stop storage from getting too
// big.
// It works by parsing the provided kubeconfig to get the arguments to pinniped login oidc,
// grabbing the issuer and the cache paths, then using that issuer to find and delete the entry
// in the session cache.
func newLogoutCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args:  cobra.NoArgs,
		Use:   "logout",
		Short: "Terminate the current user's session.",
	}
	flags := &logoutFlags{}

	cmd.Flags().StringVar(&flags.kubeconfigPath, "kubeconfig", os.Getenv("KUBECONFIG"), "Path to kubeconfig file")
	cmd.Flags().StringVar(&flags.kubeconfigContextOverride, "kubeconfig-context", "", "Kubeconfig context name (default: current active context)")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runLogout(flags)
	}
	return cmd
}

func runLogout(flags *logoutFlags) error {
	pLogger, err := SetLogLevel(os.LookupEnv, "Pinniped logout: ")
	if err != nil {
		plog.WarningErr("Received error while setting log level", err)
	}
	clientConfig := newClientConfig(flags.kubeconfigPath, flags.kubeconfigContextOverride)
	currentKubeConfig, err := clientConfig.RawConfig()
	if err != nil {
		return err
	}

	// start by getting the current context or another context if provided.
	contextName := currentKubeConfig.CurrentContext
	if len(flags.kubeconfigContextOverride) > 0 {
		contextName = flags.kubeconfigContextOverride
	}
	kubeContext, ok := currentKubeConfig.Contexts[contextName]
	if !ok {
		return fmt.Errorf("couldn't find current context")
	}

	// then get the authinfo associated with that context.
	authInfo := currentKubeConfig.AuthInfos[kubeContext.AuthInfo]
	if authInfo == nil {
		return fmt.Errorf("could not find auth info-- are you sure this is a Pinniped kubeconfig?")
	}

	// get the exec credential out of the authinfo and validate that it takes the shape of a pinniped login command.
	exec := authInfo.Exec
	if exec == nil {
		return fmt.Errorf("could not find exec credential-- are you sure this is a Pinniped kubeconfig?")
	}
	execArgs := exec.Args
	if execArgs == nil {
		return fmt.Errorf("could not find exec credential arguments-- are you sure this is a Pinniped kubeconfig?")
	}

	// parse the arguments in the exec credential (which should be the pinniped login command).
	loginCommand := oidcLoginCommand(oidcLoginCommandDeps{})
	err = loginCommand.ParseFlags(execArgs)
	if err != nil {
		return err
	}
	// Get the issuer flag. If this doesn't exist we have no way to get in to the cache so we have to exit.
	issuer := loginCommand.Flag("issuer").Value.String()
	if issuer == "" {
		return fmt.Errorf("could not find issuer-- are you sure this is a Pinniped kubeconfig?")
	}

	// Get the session cache. If it doesn't exist just use the default value.
	sessionCachePath := loginCommand.Flag("session-cache").Value.String()
	if sessionCachePath == "" {
		sessionCachePath = filepath.Join(mustGetConfigDir(), "sessions.yaml")
	}
	// Get the credential cache. If it doesn't exist just use the default value.
	credentialCachePath := loginCommand.Flag("credential-cache").Value.String()
	if credentialCachePath == "" {
		credentialCachePath = filepath.Join(mustGetConfigDir(), "credentials.yaml")
	}

	// TODO this should probably be a more targeted removal rather than the whole file...
	//  but that involves figuring out the cache key which is hard.
	// Remove the credential cache that stores the users x509 certificates.
	err = os.Remove(credentialCachePath)
	// a not found error is fine and we should move on and try to delete the
	// session cache if possible. Other errors might be a problem.
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Remove the cache entry for this issuer.
	var sessionOptions []filesession.Option
	sessionCache := filesession.New(sessionCachePath, sessionOptions...)
	downstreamScopes := []string{coreosoidc.ScopeOfflineAccess, coreosoidc.ScopeOpenID, "pinniped:request-audience"}
	sort.Strings(downstreamScopes)
	sessionCacheKey := oidcclient.SessionCacheKey{
		Issuer:      issuer,
		ClientID:    "pinniped-cli",
		Scopes:      downstreamScopes,
		RedirectURI: (&url.URL{Scheme: "http", Host: "localhost:0", Path: "/callback"}).String(),
	}
	deleted := sessionCache.DeleteToken(sessionCacheKey)

	if deleted {
		pLogger.Warning("Successfully logged out of session.")
	} else {
		// this is likely because you're already logged out, but you might still want to know.
		pLogger.Warning("Could not find session to log out of.")
		pLogger.Debug("debug info", "issuer", issuer, "session cache path", sessionCachePath, "credential cache path", credentialCachePath)
	}

	return nil
}
