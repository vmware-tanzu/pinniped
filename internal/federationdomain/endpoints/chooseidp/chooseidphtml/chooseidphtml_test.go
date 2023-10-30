// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package chooseidphtml

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/testutil"
)

var (
	testExpectedCSS = `html{height:100%}body{font-family:metropolis-light,Helvetica,sans-serif;display:flex;flex-flow:column wrap;justify-content:flex-start;align-items:center;background:linear-gradient(to top,#f8f8f8,white);min-height:100%}h1{font-size:20px;margin:0}.box{display:flex;flex-direction:column;flex-wrap:nowrap;border-radius:4px;border-color:#ddd;border-width:1px;border-style:solid;width:400px;padding:30px 30px 0;margin:60px 20px 0;background:#fff;font-size:14px}button{color:inherit;font:inherit;border:0;margin:0;outline:0;padding:0}.form-field{display:flex;margin-bottom:30px}.form-field button{width:100%;padding:1em;background-color:#218fcf;color:#eee;font-weight:700;cursor:pointer;transition:all .3s}.form-field button:focus,.form-field button:hover{background-color:#1abfd3}.form-field button:active{transform:scale(.99)}`

	testExpectedJS = `window.onload=()=>{Array.from(document.querySelectorAll("button")).forEach(e=>{e.onclick=()=>window.location.href=e.dataset.url}),document.getElementById("choose-idp-form-buttons").hidden=!1}`

	// It's okay if this changes in the future, but this gives us a chance to eyeball the formatting.
	// Our browser-based integration tests should find any incompatibilities.
	testExpectedCSP = `default-src 'none'; ` +
		`script-src 'sha256-eyuE+qQfuMn4WbDizGOp1wSGReaMYRYmRMXpyEo+8ps='; ` +
		`style-src 'sha256-SgeTG5HEbHNFgjH+EvLrC+VKZRZQ6iAI3oFnW7i/Tm4='; ` +
		`img-src data:; ` +
		`frame-ancestors 'none'`
)

func TestTemplate(t *testing.T) {
	const (
		testUpstreamName1 = "test-idp-name1"
		testUpstreamName2 = "test-idp-name2"
		testURL1          = "https://pinniped.dev/path1?query=value"
		testURL2          = "https://pinniped.dev/path2?query=value"
	)

	pageInputs := &PageData{
		IdentityProviders: []IdentityProvider{
			{DisplayName: testUpstreamName1, URL: testURL1},
			{DisplayName: testUpstreamName2, URL: testURL2},
		},
	}

	expectedHTML := testutil.ExpectedChooseIDPPageHTML(testExpectedCSS, testExpectedJS, []testutil.ChooseIDPPageExpectedValue{
		{DisplayName: testUpstreamName1, URL: testURL1},
		{DisplayName: testUpstreamName2, URL: testURL2},
	})

	var buf bytes.Buffer
	require.NoError(t, Template().Execute(&buf, pageInputs))
	require.Equal(t, expectedHTML, buf.String())
}

func TestContentSecurityPolicy(t *testing.T) {
	require.Equal(t, testExpectedCSP, ContentSecurityPolicy())
}

func TestCSS(t *testing.T) {
	require.Equal(t, testExpectedCSS, CSS())
}

func TestJS(t *testing.T) {
	require.Equal(t, testExpectedJS, JS())
}

func TestHelpers(t *testing.T) {
	require.Equal(t, "test", panicOnError("test", nil))
	require.PanicsWithError(t, "some error", func() { panicOnError("", fmt.Errorf("some error")) })
}
