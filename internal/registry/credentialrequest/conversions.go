// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package credentialrequest

import (
	loginapi "github.com/vmware-tanzu/pinniped/generated/1.19/apis/login"
	pinnipedapi "github.com/vmware-tanzu/pinniped/generated/1.19/apis/pinniped"
)

func convertToLoginAPI(input *pinnipedapi.CredentialRequest) *loginapi.TokenCredentialRequest {
	if input == nil {
		return nil
	}

	result := loginapi.TokenCredentialRequest{}
	result.ObjectMeta = input.ObjectMeta
	if input.Spec.Token != nil {
		result.Spec.Token = input.Spec.Token.Value
	}
	result.Status.Message = input.Status.Message
	if input.Status.Credential != nil {
		result.Status.Credential = &loginapi.ClusterCredential{
			ExpirationTimestamp:   input.Status.Credential.ExpirationTimestamp,
			Token:                 input.Status.Credential.Token,
			ClientCertificateData: input.Status.Credential.ClientCertificateData,
			ClientKeyData:         input.Status.Credential.ClientKeyData,
		}
	}
	return &result
}

func convertFromLoginAPI(input *loginapi.TokenCredentialRequest) *pinnipedapi.CredentialRequest {
	if input == nil {
		return nil
	}

	result := pinnipedapi.CredentialRequest{}
	result.ObjectMeta = input.ObjectMeta
	if input.Spec.Token != "" {
		result.Spec.Type = pinnipedapi.TokenCredentialType
		result.Spec.Token = &pinnipedapi.CredentialRequestTokenCredential{Value: input.Spec.Token}
	}
	result.Status.Message = input.Status.Message
	if input.Status.Credential != nil {
		result.Status.Credential = &pinnipedapi.CredentialRequestCredential{
			ExpirationTimestamp:   input.Status.Credential.ExpirationTimestamp,
			Token:                 input.Status.Credential.Token,
			ClientCertificateData: input.Status.Credential.ClientCertificateData,
			ClientKeyData:         input.Status.Credential.ClientKeyData,
		}
	}
	return &result
}
