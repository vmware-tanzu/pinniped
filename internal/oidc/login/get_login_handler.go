// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import (
	_ "embed"
	"html/template"
	"net/http"

	"go.pinniped.dev/internal/oidc"
)

var (
	//go:embed login_form.gohtml
	rawHTMLTemplate string
)

var parsedHTMLTemplate = template.Must(template.New("login_post.gohtml").Parse(rawHTMLTemplate))

type PageData struct {
	State   string
	IDPName string
}

func NewGetHandler(upstreamIDPs oidc.UpstreamIdentityProvidersLister) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, encodedState string, decodedState *oidc.UpstreamStateParamData) error {

		err := parsedHTMLTemplate.Execute(w, &PageData{State: encodedState, IDPName: decodedState.UpstreamName})
		if err != nil {
			return err
		}

		return nil
	}
}
