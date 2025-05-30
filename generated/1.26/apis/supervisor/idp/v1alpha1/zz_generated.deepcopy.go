//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ActiveDirectoryIdentityProvider) DeepCopyInto(out *ActiveDirectoryIdentityProvider) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ActiveDirectoryIdentityProvider.
func (in *ActiveDirectoryIdentityProvider) DeepCopy() *ActiveDirectoryIdentityProvider {
	if in == nil {
		return nil
	}
	out := new(ActiveDirectoryIdentityProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ActiveDirectoryIdentityProvider) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ActiveDirectoryIdentityProviderBind) DeepCopyInto(out *ActiveDirectoryIdentityProviderBind) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ActiveDirectoryIdentityProviderBind.
func (in *ActiveDirectoryIdentityProviderBind) DeepCopy() *ActiveDirectoryIdentityProviderBind {
	if in == nil {
		return nil
	}
	out := new(ActiveDirectoryIdentityProviderBind)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ActiveDirectoryIdentityProviderGroupSearch) DeepCopyInto(out *ActiveDirectoryIdentityProviderGroupSearch) {
	*out = *in
	out.Attributes = in.Attributes
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ActiveDirectoryIdentityProviderGroupSearch.
func (in *ActiveDirectoryIdentityProviderGroupSearch) DeepCopy() *ActiveDirectoryIdentityProviderGroupSearch {
	if in == nil {
		return nil
	}
	out := new(ActiveDirectoryIdentityProviderGroupSearch)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ActiveDirectoryIdentityProviderGroupSearchAttributes) DeepCopyInto(out *ActiveDirectoryIdentityProviderGroupSearchAttributes) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ActiveDirectoryIdentityProviderGroupSearchAttributes.
func (in *ActiveDirectoryIdentityProviderGroupSearchAttributes) DeepCopy() *ActiveDirectoryIdentityProviderGroupSearchAttributes {
	if in == nil {
		return nil
	}
	out := new(ActiveDirectoryIdentityProviderGroupSearchAttributes)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ActiveDirectoryIdentityProviderList) DeepCopyInto(out *ActiveDirectoryIdentityProviderList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ActiveDirectoryIdentityProvider, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ActiveDirectoryIdentityProviderList.
func (in *ActiveDirectoryIdentityProviderList) DeepCopy() *ActiveDirectoryIdentityProviderList {
	if in == nil {
		return nil
	}
	out := new(ActiveDirectoryIdentityProviderList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ActiveDirectoryIdentityProviderList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ActiveDirectoryIdentityProviderSpec) DeepCopyInto(out *ActiveDirectoryIdentityProviderSpec) {
	*out = *in
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(TLSSpec)
		(*in).DeepCopyInto(*out)
	}
	out.Bind = in.Bind
	out.UserSearch = in.UserSearch
	out.GroupSearch = in.GroupSearch
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ActiveDirectoryIdentityProviderSpec.
func (in *ActiveDirectoryIdentityProviderSpec) DeepCopy() *ActiveDirectoryIdentityProviderSpec {
	if in == nil {
		return nil
	}
	out := new(ActiveDirectoryIdentityProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ActiveDirectoryIdentityProviderStatus) DeepCopyInto(out *ActiveDirectoryIdentityProviderStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ActiveDirectoryIdentityProviderStatus.
func (in *ActiveDirectoryIdentityProviderStatus) DeepCopy() *ActiveDirectoryIdentityProviderStatus {
	if in == nil {
		return nil
	}
	out := new(ActiveDirectoryIdentityProviderStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ActiveDirectoryIdentityProviderUserSearch) DeepCopyInto(out *ActiveDirectoryIdentityProviderUserSearch) {
	*out = *in
	out.Attributes = in.Attributes
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ActiveDirectoryIdentityProviderUserSearch.
func (in *ActiveDirectoryIdentityProviderUserSearch) DeepCopy() *ActiveDirectoryIdentityProviderUserSearch {
	if in == nil {
		return nil
	}
	out := new(ActiveDirectoryIdentityProviderUserSearch)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ActiveDirectoryIdentityProviderUserSearchAttributes) DeepCopyInto(out *ActiveDirectoryIdentityProviderUserSearchAttributes) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ActiveDirectoryIdentityProviderUserSearchAttributes.
func (in *ActiveDirectoryIdentityProviderUserSearchAttributes) DeepCopy() *ActiveDirectoryIdentityProviderUserSearchAttributes {
	if in == nil {
		return nil
	}
	out := new(ActiveDirectoryIdentityProviderUserSearchAttributes)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateAuthorityDataSourceSpec) DeepCopyInto(out *CertificateAuthorityDataSourceSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateAuthorityDataSourceSpec.
func (in *CertificateAuthorityDataSourceSpec) DeepCopy() *CertificateAuthorityDataSourceSpec {
	if in == nil {
		return nil
	}
	out := new(CertificateAuthorityDataSourceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitHubAPIConfig) DeepCopyInto(out *GitHubAPIConfig) {
	*out = *in
	if in.Host != nil {
		in, out := &in.Host, &out.Host
		*out = new(string)
		**out = **in
	}
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(TLSSpec)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitHubAPIConfig.
func (in *GitHubAPIConfig) DeepCopy() *GitHubAPIConfig {
	if in == nil {
		return nil
	}
	out := new(GitHubAPIConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitHubAllowAuthenticationSpec) DeepCopyInto(out *GitHubAllowAuthenticationSpec) {
	*out = *in
	in.Organizations.DeepCopyInto(&out.Organizations)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitHubAllowAuthenticationSpec.
func (in *GitHubAllowAuthenticationSpec) DeepCopy() *GitHubAllowAuthenticationSpec {
	if in == nil {
		return nil
	}
	out := new(GitHubAllowAuthenticationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitHubClaims) DeepCopyInto(out *GitHubClaims) {
	*out = *in
	if in.Username != nil {
		in, out := &in.Username, &out.Username
		*out = new(GitHubUsernameAttribute)
		**out = **in
	}
	if in.Groups != nil {
		in, out := &in.Groups, &out.Groups
		*out = new(GitHubGroupNameAttribute)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitHubClaims.
func (in *GitHubClaims) DeepCopy() *GitHubClaims {
	if in == nil {
		return nil
	}
	out := new(GitHubClaims)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitHubClientSpec) DeepCopyInto(out *GitHubClientSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitHubClientSpec.
func (in *GitHubClientSpec) DeepCopy() *GitHubClientSpec {
	if in == nil {
		return nil
	}
	out := new(GitHubClientSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitHubIdentityProvider) DeepCopyInto(out *GitHubIdentityProvider) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitHubIdentityProvider.
func (in *GitHubIdentityProvider) DeepCopy() *GitHubIdentityProvider {
	if in == nil {
		return nil
	}
	out := new(GitHubIdentityProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GitHubIdentityProvider) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitHubIdentityProviderList) DeepCopyInto(out *GitHubIdentityProviderList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]GitHubIdentityProvider, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitHubIdentityProviderList.
func (in *GitHubIdentityProviderList) DeepCopy() *GitHubIdentityProviderList {
	if in == nil {
		return nil
	}
	out := new(GitHubIdentityProviderList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GitHubIdentityProviderList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitHubIdentityProviderSpec) DeepCopyInto(out *GitHubIdentityProviderSpec) {
	*out = *in
	in.GitHubAPI.DeepCopyInto(&out.GitHubAPI)
	in.Claims.DeepCopyInto(&out.Claims)
	in.AllowAuthentication.DeepCopyInto(&out.AllowAuthentication)
	out.Client = in.Client
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitHubIdentityProviderSpec.
func (in *GitHubIdentityProviderSpec) DeepCopy() *GitHubIdentityProviderSpec {
	if in == nil {
		return nil
	}
	out := new(GitHubIdentityProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitHubIdentityProviderStatus) DeepCopyInto(out *GitHubIdentityProviderStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitHubIdentityProviderStatus.
func (in *GitHubIdentityProviderStatus) DeepCopy() *GitHubIdentityProviderStatus {
	if in == nil {
		return nil
	}
	out := new(GitHubIdentityProviderStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitHubOrganizationsSpec) DeepCopyInto(out *GitHubOrganizationsSpec) {
	*out = *in
	if in.Policy != nil {
		in, out := &in.Policy, &out.Policy
		*out = new(GitHubAllowedAuthOrganizationsPolicy)
		**out = **in
	}
	if in.Allowed != nil {
		in, out := &in.Allowed, &out.Allowed
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitHubOrganizationsSpec.
func (in *GitHubOrganizationsSpec) DeepCopy() *GitHubOrganizationsSpec {
	if in == nil {
		return nil
	}
	out := new(GitHubOrganizationsSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LDAPIdentityProvider) DeepCopyInto(out *LDAPIdentityProvider) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LDAPIdentityProvider.
func (in *LDAPIdentityProvider) DeepCopy() *LDAPIdentityProvider {
	if in == nil {
		return nil
	}
	out := new(LDAPIdentityProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *LDAPIdentityProvider) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LDAPIdentityProviderBind) DeepCopyInto(out *LDAPIdentityProviderBind) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LDAPIdentityProviderBind.
func (in *LDAPIdentityProviderBind) DeepCopy() *LDAPIdentityProviderBind {
	if in == nil {
		return nil
	}
	out := new(LDAPIdentityProviderBind)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LDAPIdentityProviderGroupSearch) DeepCopyInto(out *LDAPIdentityProviderGroupSearch) {
	*out = *in
	out.Attributes = in.Attributes
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LDAPIdentityProviderGroupSearch.
func (in *LDAPIdentityProviderGroupSearch) DeepCopy() *LDAPIdentityProviderGroupSearch {
	if in == nil {
		return nil
	}
	out := new(LDAPIdentityProviderGroupSearch)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LDAPIdentityProviderGroupSearchAttributes) DeepCopyInto(out *LDAPIdentityProviderGroupSearchAttributes) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LDAPIdentityProviderGroupSearchAttributes.
func (in *LDAPIdentityProviderGroupSearchAttributes) DeepCopy() *LDAPIdentityProviderGroupSearchAttributes {
	if in == nil {
		return nil
	}
	out := new(LDAPIdentityProviderGroupSearchAttributes)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LDAPIdentityProviderList) DeepCopyInto(out *LDAPIdentityProviderList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]LDAPIdentityProvider, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LDAPIdentityProviderList.
func (in *LDAPIdentityProviderList) DeepCopy() *LDAPIdentityProviderList {
	if in == nil {
		return nil
	}
	out := new(LDAPIdentityProviderList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *LDAPIdentityProviderList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LDAPIdentityProviderSpec) DeepCopyInto(out *LDAPIdentityProviderSpec) {
	*out = *in
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(TLSSpec)
		(*in).DeepCopyInto(*out)
	}
	out.Bind = in.Bind
	out.UserSearch = in.UserSearch
	out.GroupSearch = in.GroupSearch
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LDAPIdentityProviderSpec.
func (in *LDAPIdentityProviderSpec) DeepCopy() *LDAPIdentityProviderSpec {
	if in == nil {
		return nil
	}
	out := new(LDAPIdentityProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LDAPIdentityProviderStatus) DeepCopyInto(out *LDAPIdentityProviderStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LDAPIdentityProviderStatus.
func (in *LDAPIdentityProviderStatus) DeepCopy() *LDAPIdentityProviderStatus {
	if in == nil {
		return nil
	}
	out := new(LDAPIdentityProviderStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LDAPIdentityProviderUserSearch) DeepCopyInto(out *LDAPIdentityProviderUserSearch) {
	*out = *in
	out.Attributes = in.Attributes
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LDAPIdentityProviderUserSearch.
func (in *LDAPIdentityProviderUserSearch) DeepCopy() *LDAPIdentityProviderUserSearch {
	if in == nil {
		return nil
	}
	out := new(LDAPIdentityProviderUserSearch)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LDAPIdentityProviderUserSearchAttributes) DeepCopyInto(out *LDAPIdentityProviderUserSearchAttributes) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LDAPIdentityProviderUserSearchAttributes.
func (in *LDAPIdentityProviderUserSearchAttributes) DeepCopy() *LDAPIdentityProviderUserSearchAttributes {
	if in == nil {
		return nil
	}
	out := new(LDAPIdentityProviderUserSearchAttributes)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCAuthorizationConfig) DeepCopyInto(out *OIDCAuthorizationConfig) {
	*out = *in
	if in.AdditionalScopes != nil {
		in, out := &in.AdditionalScopes, &out.AdditionalScopes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.AdditionalAuthorizeParameters != nil {
		in, out := &in.AdditionalAuthorizeParameters, &out.AdditionalAuthorizeParameters
		*out = make([]Parameter, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCAuthorizationConfig.
func (in *OIDCAuthorizationConfig) DeepCopy() *OIDCAuthorizationConfig {
	if in == nil {
		return nil
	}
	out := new(OIDCAuthorizationConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCClaims) DeepCopyInto(out *OIDCClaims) {
	*out = *in
	if in.AdditionalClaimMappings != nil {
		in, out := &in.AdditionalClaimMappings, &out.AdditionalClaimMappings
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCClaims.
func (in *OIDCClaims) DeepCopy() *OIDCClaims {
	if in == nil {
		return nil
	}
	out := new(OIDCClaims)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCClient) DeepCopyInto(out *OIDCClient) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCClient.
func (in *OIDCClient) DeepCopy() *OIDCClient {
	if in == nil {
		return nil
	}
	out := new(OIDCClient)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCIdentityProvider) DeepCopyInto(out *OIDCIdentityProvider) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCIdentityProvider.
func (in *OIDCIdentityProvider) DeepCopy() *OIDCIdentityProvider {
	if in == nil {
		return nil
	}
	out := new(OIDCIdentityProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *OIDCIdentityProvider) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCIdentityProviderList) DeepCopyInto(out *OIDCIdentityProviderList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]OIDCIdentityProvider, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCIdentityProviderList.
func (in *OIDCIdentityProviderList) DeepCopy() *OIDCIdentityProviderList {
	if in == nil {
		return nil
	}
	out := new(OIDCIdentityProviderList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *OIDCIdentityProviderList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCIdentityProviderSpec) DeepCopyInto(out *OIDCIdentityProviderSpec) {
	*out = *in
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(TLSSpec)
		(*in).DeepCopyInto(*out)
	}
	in.AuthorizationConfig.DeepCopyInto(&out.AuthorizationConfig)
	in.Claims.DeepCopyInto(&out.Claims)
	out.Client = in.Client
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCIdentityProviderSpec.
func (in *OIDCIdentityProviderSpec) DeepCopy() *OIDCIdentityProviderSpec {
	if in == nil {
		return nil
	}
	out := new(OIDCIdentityProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCIdentityProviderStatus) DeepCopyInto(out *OIDCIdentityProviderStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCIdentityProviderStatus.
func (in *OIDCIdentityProviderStatus) DeepCopy() *OIDCIdentityProviderStatus {
	if in == nil {
		return nil
	}
	out := new(OIDCIdentityProviderStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Parameter) DeepCopyInto(out *Parameter) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Parameter.
func (in *Parameter) DeepCopy() *Parameter {
	if in == nil {
		return nil
	}
	out := new(Parameter)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSSpec) DeepCopyInto(out *TLSSpec) {
	*out = *in
	if in.CertificateAuthorityDataSource != nil {
		in, out := &in.CertificateAuthorityDataSource, &out.CertificateAuthorityDataSource
		*out = new(CertificateAuthorityDataSourceSpec)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSSpec.
func (in *TLSSpec) DeepCopy() *TLSSpec {
	if in == nil {
		return nil
	}
	out := new(TLSSpec)
	in.DeepCopyInto(out)
	return out
}
