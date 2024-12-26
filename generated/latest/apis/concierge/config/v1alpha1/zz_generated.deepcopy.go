//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CredentialIssuer) DeepCopyInto(out *CredentialIssuer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CredentialIssuer.
func (in *CredentialIssuer) DeepCopy() *CredentialIssuer {
	if in == nil {
		return nil
	}
	out := new(CredentialIssuer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CredentialIssuer) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CredentialIssuerFrontend) DeepCopyInto(out *CredentialIssuerFrontend) {
	*out = *in
	if in.TokenCredentialRequestAPIInfo != nil {
		in, out := &in.TokenCredentialRequestAPIInfo, &out.TokenCredentialRequestAPIInfo
		*out = new(TokenCredentialRequestAPIInfo)
		**out = **in
	}
	if in.ImpersonationProxyInfo != nil {
		in, out := &in.ImpersonationProxyInfo, &out.ImpersonationProxyInfo
		*out = new(ImpersonationProxyInfo)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CredentialIssuerFrontend.
func (in *CredentialIssuerFrontend) DeepCopy() *CredentialIssuerFrontend {
	if in == nil {
		return nil
	}
	out := new(CredentialIssuerFrontend)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CredentialIssuerList) DeepCopyInto(out *CredentialIssuerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CredentialIssuer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CredentialIssuerList.
func (in *CredentialIssuerList) DeepCopy() *CredentialIssuerList {
	if in == nil {
		return nil
	}
	out := new(CredentialIssuerList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CredentialIssuerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CredentialIssuerSpec) DeepCopyInto(out *CredentialIssuerSpec) {
	*out = *in
	if in.ImpersonationProxy != nil {
		in, out := &in.ImpersonationProxy, &out.ImpersonationProxy
		*out = new(ImpersonationProxySpec)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CredentialIssuerSpec.
func (in *CredentialIssuerSpec) DeepCopy() *CredentialIssuerSpec {
	if in == nil {
		return nil
	}
	out := new(CredentialIssuerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CredentialIssuerStatus) DeepCopyInto(out *CredentialIssuerStatus) {
	*out = *in
	if in.Strategies != nil {
		in, out := &in.Strategies, &out.Strategies
		*out = make([]CredentialIssuerStrategy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CredentialIssuerStatus.
func (in *CredentialIssuerStatus) DeepCopy() *CredentialIssuerStatus {
	if in == nil {
		return nil
	}
	out := new(CredentialIssuerStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CredentialIssuerStrategy) DeepCopyInto(out *CredentialIssuerStrategy) {
	*out = *in
	in.LastUpdateTime.DeepCopyInto(&out.LastUpdateTime)
	if in.Frontend != nil {
		in, out := &in.Frontend, &out.Frontend
		*out = new(CredentialIssuerFrontend)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CredentialIssuerStrategy.
func (in *CredentialIssuerStrategy) DeepCopy() *CredentialIssuerStrategy {
	if in == nil {
		return nil
	}
	out := new(CredentialIssuerStrategy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImpersonationProxyInfo) DeepCopyInto(out *ImpersonationProxyInfo) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImpersonationProxyInfo.
func (in *ImpersonationProxyInfo) DeepCopy() *ImpersonationProxyInfo {
	if in == nil {
		return nil
	}
	out := new(ImpersonationProxyInfo)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImpersonationProxyServiceSpec) DeepCopyInto(out *ImpersonationProxyServiceSpec) {
	*out = *in
	if in.Annotations != nil {
		in, out := &in.Annotations, &out.Annotations
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImpersonationProxyServiceSpec.
func (in *ImpersonationProxyServiceSpec) DeepCopy() *ImpersonationProxyServiceSpec {
	if in == nil {
		return nil
	}
	out := new(ImpersonationProxyServiceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImpersonationProxySpec) DeepCopyInto(out *ImpersonationProxySpec) {
	*out = *in
	in.Service.DeepCopyInto(&out.Service)
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(ImpersonationProxyTLSSpec)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImpersonationProxySpec.
func (in *ImpersonationProxySpec) DeepCopy() *ImpersonationProxySpec {
	if in == nil {
		return nil
	}
	out := new(ImpersonationProxySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImpersonationProxyTLSSpec) DeepCopyInto(out *ImpersonationProxyTLSSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImpersonationProxyTLSSpec.
func (in *ImpersonationProxyTLSSpec) DeepCopy() *ImpersonationProxyTLSSpec {
	if in == nil {
		return nil
	}
	out := new(ImpersonationProxyTLSSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TokenCredentialRequestAPIInfo) DeepCopyInto(out *TokenCredentialRequestAPIInfo) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TokenCredentialRequestAPIInfo.
func (in *TokenCredentialRequestAPIInfo) DeepCopy() *TokenCredentialRequestAPIInfo {
	if in == nil {
		return nil
	}
	out := new(TokenCredentialRequestAPIInfo)
	in.DeepCopyInto(out)
	return out
}
