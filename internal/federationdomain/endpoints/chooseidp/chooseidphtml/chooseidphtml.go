// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package chooseidphtml

import (
	_ "embed" // Needed to trigger //go:embed directives below.
	"html/template"
	"strings"

	"github.com/tdewolff/minify/v2/minify"

	"go.pinniped.dev/internal/federationdomain/csp"
)

//nolint:gochecknoglobals // This package uses globals to ensure that all parsing and minifying happens at init.
var (
	//go:embed choose_idp.css
	rawCSS      string
	minifiedCSS = panicOnError(minify.CSS(rawCSS))

	//go:embed choose_idp.js
	rawJS      string
	minifiedJS = panicOnError(minify.JS(rawJS))

	//go:embed choose_idp.gohtml
	rawHTMLTemplate string

	// Parse the Go templated HTML and inject functions providing the minified inline CSS and JS.
	parsedHTMLTemplate = template.Must(template.New("choose_idp.gohtml").Funcs(template.FuncMap{
		"minifiedCSS": func() template.CSS { return template.CSS(CSS()) }, //nolint:gosec // This is 100% static input, not attacker-controlled.
		"minifiedJS":  func() template.JS { return template.JS(JS()) },    //nolint:gosec // This is 100% static input, not attacker-controlled.
	}).Parse(rawHTMLTemplate))

	// Generate the CSP header value once since it's effectively constant.
	cspValue = strings.Join([]string{
		`default-src 'none'`,
		`script-src '` + csp.Hash(minifiedJS) + `'`,
		`style-src '` + csp.Hash(minifiedCSS) + `'`,
		`img-src data:`,
		`frame-ancestors 'none'`,
	}, "; ")
)

func panicOnError(s string, err error) string {
	if err != nil {
		panic(err)
	}
	return s
}

// ContentSecurityPolicy returns the Content-Security-Policy header value to make the Template() operate correctly.
//
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy.
func ContentSecurityPolicy() string { return cspValue }

// Template returns the html/template.Template for rendering the login page.
func Template() *template.Template { return parsedHTMLTemplate }

// CSS returns the minified CSS that will be embedded into the page template.
func CSS() string { return minifiedCSS }

// JS returns the minified JS that will be embedded into the page template.
func JS() string { return minifiedJS }

type IdentityProvider struct {
	DisplayName string
	URL         string
}

// PageData represents the inputs to the template.
type PageData struct {
	IdentityProviders []IdentityProvider
}
