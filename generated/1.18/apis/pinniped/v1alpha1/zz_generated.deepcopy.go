// +build !ignore_autogenerated

// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CredentialRequest) DeepCopyInto(out *CredentialRequest) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CredentialRequest.
func (in *CredentialRequest) DeepCopy() *CredentialRequest {
	if in == nil {
		return nil
	}
	out := new(CredentialRequest)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CredentialRequest) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CredentialRequestCredential) DeepCopyInto(out *CredentialRequestCredential) {
	*out = *in
	in.ExpirationTimestamp.DeepCopyInto(&out.ExpirationTimestamp)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CredentialRequestCredential.
func (in *CredentialRequestCredential) DeepCopy() *CredentialRequestCredential {
	if in == nil {
		return nil
	}
	out := new(CredentialRequestCredential)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CredentialRequestList) DeepCopyInto(out *CredentialRequestList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CredentialRequest, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CredentialRequestList.
func (in *CredentialRequestList) DeepCopy() *CredentialRequestList {
	if in == nil {
		return nil
	}
	out := new(CredentialRequestList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CredentialRequestList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CredentialRequestSpec) DeepCopyInto(out *CredentialRequestSpec) {
	*out = *in
	if in.Token != nil {
		in, out := &in.Token, &out.Token
		*out = new(CredentialRequestTokenCredential)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CredentialRequestSpec.
func (in *CredentialRequestSpec) DeepCopy() *CredentialRequestSpec {
	if in == nil {
		return nil
	}
	out := new(CredentialRequestSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CredentialRequestStatus) DeepCopyInto(out *CredentialRequestStatus) {
	*out = *in
	if in.Credential != nil {
		in, out := &in.Credential, &out.Credential
		*out = new(CredentialRequestCredential)
		(*in).DeepCopyInto(*out)
	}
	if in.Message != nil {
		in, out := &in.Message, &out.Message
		*out = new(string)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CredentialRequestStatus.
func (in *CredentialRequestStatus) DeepCopy() *CredentialRequestStatus {
	if in == nil {
		return nil
	}
	out := new(CredentialRequestStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CredentialRequestTokenCredential) DeepCopyInto(out *CredentialRequestTokenCredential) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CredentialRequestTokenCredential.
func (in *CredentialRequestTokenCredential) DeepCopy() *CredentialRequestTokenCredential {
	if in == nil {
		return nil
	}
	out := new(CredentialRequestTokenCredential)
	in.DeepCopyInto(out)
	return out
}
