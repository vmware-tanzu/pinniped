// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authenticationv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/authentication/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
)

func main() {
	reqJSON, err := json.Marshal(&loginv1alpha1.TokenCredentialRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: os.Getenv("PINNIPED_TEST_CONCIERGE_NAMESPACE"),
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "TokenCredentialRequest",
			APIVersion: loginv1alpha1.GroupName + "/v1alpha1",
		},
		Spec: loginv1alpha1.TokenCredentialRequestSpec{
			Token: os.Getenv("PINNIPED_TEST_USER_TOKEN"),
			Authenticator: corev1.TypedLocalObjectReference{
				APIGroup: &authenticationv1alpha1.SchemeGroupVersion.Group,
				Kind:     os.Getenv("PINNIPED_AUTHENTICATOR_KIND"),
				Name:     os.Getenv("PINNIPED_AUTHENTICATOR_NAME"),
			},
		},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(reqJSON))
}
