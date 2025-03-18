// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"k8s.io/apimachinery/pkg/util/validation/field"

	identityapi "go.pinniped.dev/generated/1.32/apis/concierge/identity"
)

func ValidateWhoAmIRequest(whoAmIRequest *identityapi.WhoAmIRequest) field.ErrorList {
	return nil // add validation for spec here if we expand it
}
