// Copyright 2022-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package loginhtml

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/testutil"
)

var (
	testExpectedCSS = `html{height:100%}body{font-family:metropolis-light,Helvetica,sans-serif;display:flex;flex-flow:column wrap;justify-content:flex-start;align-items:center;background:linear-gradient(to top,#f8f8f8,white);min-height:100%}h1{font-size:20px;margin:0}.box{display:flex;flex-direction:column;flex-wrap:nowrap;border-radius:4px;border-color:#ddd;border-width:1px;border-style:solid;width:400px;padding:30px 30px 0;margin:60px 20px 0;background:#fff;font-size:14px}input{color:inherit;font:inherit;border:0;margin:0;outline:0;padding:0}.form-field{display:flex;margin-bottom:30px}.form-field input[type=password],.form-field input[type=text],.form-field input[type=submit]{width:100%;padding:1em}.form-field input[type=password],.form-field input[type=text]{border-radius:3px;border-width:1px;border-style:solid;border-color:#a6a6a6}.form-field input[type=submit]{background-color:#218fcf;color:#eee;font-weight:700;cursor:pointer;transition:all .3s}.form-field input[type=submit]:focus,.form-field input[type=submit]:hover{background-color:#1abfd3}.form-field input[type=submit]:active{transform:scale(.99)}.hidden{border:0;clip:rect(0 0 0 0);height:1px;margin:-1px;overflow:hidden;padding:0;position:absolute;width:1px}.alert{color:crimson}`

	// It's okay if this changes in the future, but this gives us a chance to eyeball the formatting.
	// Our browser-based integration tests should find any incompatibilities.
	testExpectedCSP = `default-src 'none'; ` +
		`style-src 'sha256-QC9ckaUFAdcN0Ysmu8q8iqCazYFgrJSQDJPa/przPXU='; ` +
		`frame-ancestors 'none'`
)

func TestTemplate(t *testing.T) {
	const (
		testUpstreamName = "test-idp-name"
		testPath         = "test-post-path"
		testEncodedState = "test-encoded-state"
		testAlert        = "test-alert-message"
	)

	var buf bytes.Buffer
	pageInputs := &PageData{
		PostPath:      testPath,
		State:         testEncodedState,
		IDPName:       testUpstreamName,
		HasAlertError: true,
		AlertMessage:  testAlert,
	}

	// Render with an alert.
	expectedHTMLWithAlert := testutil.ExpectedLoginPageHTML(testExpectedCSS, testUpstreamName, testPath, testEncodedState, testAlert)
	require.NoError(t, Template().Execute(&buf, pageInputs))
	// t.Logf("actual value:\n%s", buf.String()) // useful when updating minify library causes new output
	require.Equal(t, expectedHTMLWithAlert, buf.String())

	// Render again without an alert.
	pageInputs.HasAlertError = false
	expectedHTMLWithoutAlert := testutil.ExpectedLoginPageHTML(testExpectedCSS, testUpstreamName, testPath, testEncodedState, "")
	buf = bytes.Buffer{} // clear previous result from buffer
	require.NoError(t, Template().Execute(&buf, pageInputs))
	require.Equal(t, expectedHTMLWithoutAlert, buf.String())
}

func TestContentSecurityPolicy(t *testing.T) {
	require.Equal(t, testExpectedCSP, ContentSecurityPolicy())
}

func TestCSS(t *testing.T) {
	require.Equal(t, testExpectedCSS, CSS())
}

func TestHelpers(t *testing.T) {
	require.Equal(t, "test", panicOnError("test", nil))
	require.PanicsWithError(t, "some error", func() { panicOnError("", fmt.Errorf("some error")) })
}
