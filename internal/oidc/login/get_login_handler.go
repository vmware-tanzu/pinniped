// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import (
	_ "embed"
	"html/template"
	"net/http"

	"go.pinniped.dev/internal/oidc"
)

const defaultErrorMessage = "An internal error occurred. Please contact your administrator for help."

var (
	//go:embed login_form.gohtml
	rawHTMLTemplate string

	errorMappings = map[string]string{
		"login_error": "Incorrect username or password.",
	}
)

type PageData struct {
	State         string
	IDPName       string
	HasAlertError bool
	AlertMessage  string
	Title         string
}

func NewGetHandler(upstreamIDPs oidc.UpstreamIdentityProvidersLister) HandlerFunc {
	var parsedHTMLTemplate = template.Must(template.New("login_post.gohtml").Parse(rawHTMLTemplate))
	return func(w http.ResponseWriter, r *http.Request, encodedState string, decodedState *oidc.UpstreamStateParamData) error {
		alertError := r.URL.Query().Get("err")
		message := errorMappings[alertError]
		if message == "" {
			message = defaultErrorMessage
		}
		err := parsedHTMLTemplate.Execute(w, &PageData{
			State:         encodedState,
			IDPName:       decodedState.UpstreamName,
			HasAlertError: alertError != "",
			AlertMessage:  message,
			Title:         "Pinniped",
		})
		if err != nil {
			return err
		}

		return nil
	}
}
