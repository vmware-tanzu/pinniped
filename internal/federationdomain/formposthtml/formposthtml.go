// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package formposthtml defines HTML templates used by the Supervisor.
package formposthtml

import (
	_ "embed" // Needed to trigger //go:embed directives below.
	"html/template"
	"strings"

	"github.com/tdewolff/minify/v2/minify"

	"go.pinniped.dev/internal/federationdomain/csp"
)

//nolint:gochecknoglobals // This package uses globals to ensure that all parsing and minifying happens at init.
var (
	//go:embed form_post.css
	rawCSS      string
	minifiedCSS = panicOnError(minify.CSS(rawCSS))

	//go:embed form_post.js
	rawJS      string
	minifiedJS = panicOnError(minify.JS(rawJS))

	//go:embed form_post.gohtml
	rawHTMLTemplate string

	// Parse the Go templated HTML and inject functions providing the minified inline CSS and JS.
	parsedHTMLTemplate = template.Must(template.New("form_post.gohtml").Funcs(template.FuncMap{
		"minifiedCSS": func() template.CSS { return template.CSS(minifiedCSS) }, //nolint:gosec // This is 100% static input, not attacker-controlled.
		"minifiedJS":  func() template.JS { return template.JS(minifiedJS) },    //nolint:gosec // This is 100% static input, not attacker-controlled.
	}).Parse(rawHTMLTemplate))

	// Generate the CSP header value once since it's effectively constant.
	cspValue = strings.Join([]string{
		`default-src 'none'`,
		`script-src '` + csp.Hash(minifiedJS) + `'`,
		`style-src '` + csp.Hash(minifiedCSS) + `'`,
		`img-src data:`,
		`connect-src *`,
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

// Template returns the html/template.Template for rendering the response_type=form_post response page.
func Template() *template.Template { return parsedHTMLTemplate }
