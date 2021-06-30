// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package formposthtml defines HTML templates used by the Supervisor.
//nolint: gochecknoglobals // This package uses globals to ensure that all parsing and minifying happens at init.
package formposthtml

import (
	"crypto/sha256"
	_ "embed" // Needed to trigger //go:embed directives below.
	"encoding/base64"
	"html/template"
	"strings"

	"github.com/tdewolff/minify/v2/minify"
)

var (
	//go:embed form_post.css
	rawCSS      string
	minifiedCSS = mustMinify(minify.CSS(rawCSS))

	//go:embed form_post.js
	rawJS      string
	minifiedJS = mustMinify(minify.JS(rawJS))

	//go:embed form_post.gohtml
	rawHTMLTemplate string
)

// Parse the Go templated HTML and inject functions providing the minified inline CSS and JS.
var parsedHTMLTemplate = template.Must(template.New("form_post.gohtml").Funcs(template.FuncMap{
	"minifiedCSS": func() template.CSS { return template.CSS(minifiedCSS) },
	"minifiedJS":  func() template.JS { return template.JS(minifiedJS) }, //nolint:gosec // This is 100% static input, not attacker-controlled.
}).Parse(rawHTMLTemplate))

// Generate the CSP header value once since it's effectively constant:
var cspValue = strings.Join([]string{
	`default-src 'none'`,
	`script-src '` + cspHash(minifiedJS) + `'`,
	`style-src '` + cspHash(minifiedCSS) + `'`,
	`img-src data:`,
	`connect-src *`,
	`frame-ancestors 'none'`,
}, "; ")

func mustMinify(s string, err error) string {
	if err != nil {
		panic(err)
	}
	return s
}

func cspHash(s string) string {
	hashBytes := sha256.Sum256([]byte(s))
	return "sha256-" + base64.StdEncoding.EncodeToString(hashBytes[:])
}

// ContentSecurityPolicy returns the Content-Security-Policy header value to make the Template() operate correctly.
//
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src#:~:text=%27%3Chash-algorithm%3E-%3Cbase64-value%3E%27.
func ContentSecurityPolicy() string { return cspValue }

// Template returns the html/template.Template for rendering the response_type=form_post response page.
func Template() *template.Template { return parsedHTMLTemplate }
