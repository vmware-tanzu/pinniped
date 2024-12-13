// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import "fmt"

// KubernetesUserInfo represents the current authenticated user, exactly as Kubernetes understands it.
// Copied from the Kubernetes token review API.
type KubernetesUserInfo struct {
	// User is the UserInfo associated with the current user.
	User UserInfo `json:"user"`
	// Audiences are audience identifiers chosen by the authenticator.
	// +optional
	Audiences []string `json:"audiences,omitempty"`
}

// UserInfo holds the information about the user needed to implement the
// user.Info interface.
type UserInfo struct {
	// The name that uniquely identifies this user among all active users.
	Username string `json:"username"`
	// A unique value that identifies this user across time. If this user is
	// deleted and another user by the same name is added, they will have
	// different UIDs.
	// +optional
	UID string `json:"uid,omitempty"`
	// The names of groups this user is a part of.
	// +optional
	Groups []string `json:"groups,omitempty"`
	// Any additional information provided by the authenticator.
	// +optional
	Extra map[string]ExtraValue `json:"extra,omitempty"`
}

// ExtraValue masks the value so protobuf can generate
type ExtraValue []string

func (t ExtraValue) String() string {
	return fmt.Sprintf("%v", []string(t))
}
