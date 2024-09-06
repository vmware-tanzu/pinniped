// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phttp

import (
	"net/http"
	"os"
	"runtime"

	"golang.org/x/term"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/rest"

	"go.pinniped.dev/internal/httputil/roundtripper"
)

func warningWrapper(rt http.RoundTripper, handler rest.WarningHandler) http.RoundTripper {
	return roundtripper.WrapFunc(rt, func(req *http.Request) (*http.Response, error) {
		resp, err := rt.RoundTrip(req)

		handleWarnings(resp, handler)

		return resp, err
	})
}

func handleWarnings(resp *http.Response, handler rest.WarningHandler) {
	if resp == nil {
		return
	}

	warnings, _ := net.ParseWarningHeaders(resp.Header["Warning"]) // safe to ignore errors here
	for _, warning := range warnings {
		handler.HandleWarningHeader(warning.Code, warning.Agent, warning.Text) // client-go throws away the date
	}
}

func getWarningHandler() rest.WarningHandler {
	// the client-go rest.WarningHandlers all log warnings with non-empty message and code=299, agent is ignored

	// no deduplication or color output when running from a non-terminal such as a pod
	//nolint:gosec // this is an int, cast to uintptr, cast back to int
	if isTerm := term.IsTerminal(int(os.Stderr.Fd())); !isTerm {
		return rest.WarningLogger{}
	}

	// deduplicate and attempt color warnings when running from a terminal
	return rest.NewWarningWriter(os.Stderr, rest.WarningWriterOptions{
		Deduplicate: true,
		Color:       allowsColorOutput(),
	})
}

// allowsColorOutput returns true if the process environment indicates color output is supported and desired.
// Copied from k8s.io/kubectl/pkg/util/term.AllowsColorOutput.
func allowsColorOutput() bool {
	// https://en.wikipedia.org/wiki/Computer_terminal#Dumb_terminals
	if os.Getenv("TERM") == "dumb" {
		return false
	}

	// https://no-color.org/
	if _, nocolor := os.LookupEnv("NO_COLOR"); nocolor {
		return false
	}

	// On Windows WT_SESSION is set by the modern terminal component.
	// Older terminals have poor support for UTF-8, VT escape codes, etc.
	if runtime.GOOS == "windows" && os.Getenv("WT_SESSION") == "" {
		return false
	}

	return true
}
