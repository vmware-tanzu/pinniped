// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package loginhtml defines HTML templates used by the Supervisor.
package loginhtml

import (
	_ "embed" // Needed to trigger //go:embed directives below.
	"html/template"
	"strings"

	"github.com/tdewolff/minify/v2/minify"

	"go.pinniped.dev/internal/federationdomain/csp"
)

//nolint:gochecknoglobals // This package uses globals to ensure that all parsing and minifying happens at init.
var (
	//go:embed login_form.css
	rawCSS      string
	minifiedCSS = panicOnError(minify.CSS(rawCSS))

	//go:embed login_form.gohtml
	rawHTMLTemplate string

	// Parse the Go templated HTML and inject functions providing the minified inline CSS and JS.
	parsedHTMLTemplate = template.Must(template.New("login_form.gohtml").Funcs(template.FuncMap{
		"minifiedCSS": func() template.CSS { return template.CSS(CSS()) }, //nolint:gosec // This is 100% static input, not attacker-controlled.
	}).Parse(rawHTMLTemplate))

	// Generate the CSP header value once since it's effectively constant.
	cspValue = strings.Join([]string{
		`default-src 'none'`,
		`style-src '` + csp.Hash(minifiedCSS) + `'`,
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

// PageData represents the inputs to the template.
type PageData struct {
	State         string
	IDPName       string
	HasAlertError bool
	AlertMessage  string
	MinifiedCSS   template.CSS
	PostPath      string
}
