// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"fmt"

	"go.pinniped.dev/internal/here"
)

func ExpectedLoginPageHTML(wantCSS, wantIDPName, wantPostPath, wantEncodedState, wantAlert string) string {
	alertHTML := ""
	if wantAlert != "" {
		alertHTML = fmt.Sprintf("\n"+
			"    <div class=\"form-field\">\n"+
			"        <span class=\"alert\" role=\"alert\" aria-label=\"login error message\">%s</span>\n"+
			"    </div>\n    ",
			wantAlert,
		)
	}

	// Note that "role", "aria-*", and "alert" attributes are hints to screen readers.
	// Also note that some structure and attributes used here are hints to password managers,
	// see https://support.1password.com/compatible-website-design/.
	// Please take care when changing the HTML of this form,
	// and test with a screen reader and password manager after changes.
	return here.Docf(`<!DOCTYPE html>
        <html lang="en">
        <head>
            <title>Pinniped</title>
            <meta charset="UTF-8">
            <style>%s</style>
            <link id="favicon" rel="icon"/>
        </head>
        <body>
        <div class="box" aria-label="login form" role="main">
            <div class="form-field">
                <h1>Log in to %s</h1>
            </div>
            %s
            <form action="%s" method="post">
                <input type="hidden" name="state" id="state" value="%s">
                <div class="form-field">
                    <label for="username"><span class="hidden" aria-hidden="true">Username</span></label>
                    <input type="text" name="username" id="username"
                           autocomplete="username" placeholder="Username" required>
                </div>
                <div class="form-field">
                    <label for="password"><span class="hidden" aria-hidden="true">Password</span></label>
                    <input type="password" name="password" id="password"
                           autocomplete="current-password" placeholder="Password" required>
                </div>
                <div class="form-field">
                    <input type="submit" name="submit" id="submit" value="Log in"/>
                </div>
            </form>
        </div>
        </body>
        </html>
	`,
		wantCSS,
		wantIDPName,
		alertHTML,
		wantPostPath,
		wantEncodedState,
	)
}
