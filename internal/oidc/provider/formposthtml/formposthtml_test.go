// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formposthtml

import (
	"bytes"
	"fmt"
	"net/url"
	"testing"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
)

var (
	testRedirectURL = "http://127.0.0.1:12345/callback"

	testResponseParams = url.Values{
		"code":  []string{"test-S629KHsCCBYV0PQ6FDSrn6iEXtVImQRBh7NCAk.JezyUSdCiSslYjtUmv7V5VAgiCz3ZkES9mYldg9GhqU"},
		"scope": []string{"openid offline_access pinniped:request-audience"},
		"state": []string{"01234567890123456789012345678901"},
	}

	testExpectedFormPostOutput = here.Doc(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <style>body{font-family:metropolis-light,Helvetica,sans-serif}h1{font-size:20px}.state{position:absolute;top:100px;left:50%;width:400px;height:80px;margin-top:-40px;margin-left:-200px;font-size:14px;line-height:24px}button{margin:-10px;padding:10px;text-align:left;width:100%;display:inline;border:none;background:0 0;cursor:pointer;transition:all .1s}button:hover{background-color:#eee;transform:scale(1.01)}button:active{background-color:#ddd;transform:scale(.99)}code{display:block;word-wrap:break-word;word-break:break-all;font-size:12px;font-family:monospace;color:#333}.copy-icon{float:left;width:36px;height:36px;margin-top:-3px;margin-right:10px;background-size:contain;background-repeat:no-repeat;background-image:url("data:image/svg+xml,%3Csvg width=%2236%22 height=%2236%22 viewBox=%220 0 36 36%22 xmlns=%22http://www.w3.org/2000/svg%22 xmlns:xlink=%22http://www.w3.org/1999/xlink%22%3E%3Ctitle%3Ecopy-to-clipboard-line%3C/title%3E%3Cpath d=%22M22.6 4H21.55a3.89 3.89.0 00-7.31.0H13.4A2.41 2.41.0 0011 6.4V10H25V6.4A2.41 2.41.0 0022.6 4zM23 8H13V6.25A.25.25.0 0113.25 6h2.69l.12-1.11A1.24 1.24.0 0116.61 4a2 2 0 013.15 1.18l.09.84h2.9a.25.25.0 01.25.25z%22 class=%22clr-i-outline clr-i-outline-path-1%22/%3E%3Cpath d=%22M33.25 18.06H21.33l2.84-2.83a1 1 0 10-1.42-1.42L17.5 19.06l5.25 5.25a1 1 0 00.71.29 1 1 0 00.71-1.7l-2.84-2.84H33.25a1 1 0 000-2z%22 class=%22clr-i-outline clr-i-outline-path-2%22/%3E%3Cpath d=%22M29 16h2V6.68A1.66 1.66.0 0029.35 5H27.08V7H29z%22 class=%22clr-i-outline clr-i-outline-path-3%22/%3E%3Cpath d=%22M29 31H7V7H9V5H6.64A1.66 1.66.0 005 6.67V31.32A1.66 1.66.0 006.65 33H29.36A1.66 1.66.0 0031 31.33V22.06H29z%22 class=%22clr-i-outline clr-i-outline-path-4%22/%3E%3Crect x=%220%22 y=%220%22 width=%2236%22 height=%2236%22 fill-opacity=%220%22/%3E%3C/svg%3E")}@keyframes loader{to{transform:rotate(360deg)}}#loading{content:'';box-sizing:border-box;width:80px;height:80px;margin-top:-40px;margin-left:-40px;border-radius:50%;border:2px solid #fff;border-top-color:#1b3951;animation:loader .6s linear infinite}</style>
            <script>window.onload=()=>{const e=t=>{Array.from(document.querySelectorAll('.state')).forEach(e=>e.hidden=!0);const e=document.getElementById(t);e.hidden=!1,document.title=e.dataset.title,document.getElementById('favicon').setAttribute('href','data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>'+e.dataset.favicon+'</text></svg>')};e('loading'),window.history.replaceState(null,'','./'),document.getElementById('manual-copy-button').onclick=()=>{const e=document.getElementById('manual-copy-button').innerText;navigator.clipboard.writeText(e).then(()=>console.info('copied authorization code '+e+' to clipboard')).catch(t=>console.error('failed to copy code '+e+' to clipboard: '+t))};const n=setTimeout(()=>e('manual'),2e3),t=document.forms[0].elements;fetch(t.redirect_uri.value,{method:'POST',mode:'no-cors',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body:t.encoded_params.value}).then(()=>clearTimeout(n)).then(()=>e('success')).catch(()=>e('manual'))}</script>
            <link id="favicon" rel="icon"/>
        </head>
        <body>
        <noscript>
            To finish logging in, paste this authorization code into your command-line session: test-S629KHsCCBYV0PQ6FDSrn6iEXtVImQRBh7NCAk.JezyUSdCiSslYjtUmv7V5VAgiCz3ZkES9mYldg9GhqU
        </noscript>
        <form>
            <input type="hidden" name="redirect_uri" value="http://127.0.0.1:12345/callback"/>
            <input type="hidden" name="encoded_params" value="code=test-S629KHsCCBYV0PQ6FDSrn6iEXtVImQRBh7NCAk.JezyUSdCiSslYjtUmv7V5VAgiCz3ZkES9mYldg9GhqU&amp;scope=openid&#43;offline_access&#43;pinniped%3Arequest-audience&amp;state=01234567890123456789012345678901"/>
        </form>
        <div id="loading" class="state" data-favicon="⏳" data-title="Logging in..." hidden></div>
        <div id="success" class="state" data-favicon="✅" data-title="Login succeeded" hidden>
            <h1>Login succeeded</h1>
            <p>You have successfully logged in. You may now close this tab.</p>
        </div>
        <div id="manual" class="state" data-favicon="⌛" data-title="Finish your login" hidden>
            <h1>Finish your login</h1>
            <p>To finish logging in, paste this authorization code into your command-line session:</p>
            <button id="manual-copy-button">
                <span class="copy-icon"></span>
                <code id="manual-auth-code">test-S629KHsCCBYV0PQ6FDSrn6iEXtVImQRBh7NCAk.JezyUSdCiSslYjtUmv7V5VAgiCz3ZkES9mYldg9GhqU</code>
            </button>
        </div>
        </body>
        </html>
		`)

	// It's okay if this changes in the future, but this gives us a chance to eyeball the formatting.
	// Our browser-based integration tests should find any incompatibilities.
	testExpectedCSP = `default-src 'none'; ` +
		`script-src 'sha256-cjTdJmRvuz5EHNb/cw6pFk9iWyjegU9Ihx7Fb9tlqRg='; ` +
		`style-src 'sha256-CtfkX7m8x2UdGYvGgDq+6b6yIAQsASW9pbQK+sG8fNA='; ` +
		`img-src data:; ` +
		`connect-src *; ` +
		`frame-ancestors 'none'`
)

func TestTemplate(t *testing.T) {
	// Use the Fosite helper to render the form, ensuring that the parameters all have the same names + types.
	var buf bytes.Buffer
	fosite.WriteAuthorizeFormPostResponse(testRedirectURL, testResponseParams, Template(), &buf)

	// Render again so we can confirm that there is no error returned (Fosite ignores any error).
	var buf2 bytes.Buffer
	require.NoError(t, Template().Execute(&buf2, struct {
		RedirURL   string
		Parameters url.Values
	}{
		RedirURL:   testRedirectURL,
		Parameters: testResponseParams,
	}))

	// t.Logf("actual value:\n%s", buf2.String()) // useful when updating minify library causes new output
	require.Equal(t, buf.String(), buf2.String())
	require.Equal(t, testExpectedFormPostOutput, buf.String())
}

func TestContentSecurityPolicyHashes(t *testing.T) {
	require.Equal(t, testExpectedCSP, ContentSecurityPolicy())
}

func TestHelpers(t *testing.T) {
	// These are silly tests but it's easy to we might as well have them.
	require.Equal(t, "test", mustMinify("test", nil))
	require.PanicsWithError(t, "some error", func() { mustMinify("", fmt.Errorf("some error")) })

	// Example test vector from https://content-security-policy.com/hash/.
	require.Equal(t, "sha256-RFWPLDbv2BY+rCkDzsE+0fr8ylGr2R2faWMhq4lfEQc=", cspHash("doSomething();"))
}
