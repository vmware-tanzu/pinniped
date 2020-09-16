// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package api

// Annotation on service.
const SecretNameAnnotation = "service.placeholder.io/secret-name"

// Annotations on secret.
const (
	// ServiceUIDAnnotation is an annotation on a secret that indicates which service created it, by UID.
	ServiceUIDAnnotation = "service.placeholder.io/service-uid"

	// ServiceNameAnnotation is an annotation on a secret that indicates which service created it, by Name
	// to allow reverse lookups on services for comparison against UIDs.
	ServiceNameAnnotation = "service.placeholder.io/service-name"
)

const SecretDataKey = "secret-data"
