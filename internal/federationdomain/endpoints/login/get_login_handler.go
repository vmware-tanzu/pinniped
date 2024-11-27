// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"net/http"

	"go.pinniped.dev/internal/federationdomain/endpoints/login/loginhtml"
	"go.pinniped.dev/internal/federationdomain/endpoints/loginurl"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/stateparam"
)

const (
	internalErrorMessage                    = "An internal error occurred. Please contact your administrator for help."
	incorrectUsernameOrPasswordErrorMessage = "Incorrect username or password."
)

func NewGetHandler(loginPath string) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, encodedState stateparam.Encoded, decodedState *oidc.UpstreamStateParamData) error {
		alertMessage, hasAlert := getAlert(r)

		pageInputs := &loginhtml.PageData{
			PostPath:      loginPath,
			State:         encodedState.String(),
			IDPName:       decodedState.UpstreamName,
			HasAlertError: hasAlert,
			AlertMessage:  alertMessage,
		}
		return loginhtml.Template().Execute(w, pageInputs)
	}
}

func getAlert(r *http.Request) (string, bool) {
	errorParamValue := r.URL.Query().Get(loginurl.ErrParamName)

	message := internalErrorMessage
	if errorParamValue == string(loginurl.ShowBadUserPassErr) {
		message = incorrectUsernameOrPasswordErrorMessage
	}

	return message, errorParamValue != ""
}
