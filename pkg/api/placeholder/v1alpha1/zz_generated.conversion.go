// +build !ignore_autogenerated

/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by conversion-gen. DO NOT EDIT.

package v1alpha1

import (
	unsafe "unsafe"

	placeholder "github.com/suzerain-io/placeholder-name/pkg/api/placeholder"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*LoginRequest)(nil), (*placeholder.LoginRequest)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_LoginRequest_To_placeholder_LoginRequest(a.(*LoginRequest), b.(*placeholder.LoginRequest), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*placeholder.LoginRequest)(nil), (*LoginRequest)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_placeholder_LoginRequest_To_v1alpha1_LoginRequest(a.(*placeholder.LoginRequest), b.(*LoginRequest), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*LoginRequestCredential)(nil), (*placeholder.LoginRequestCredential)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_LoginRequestCredential_To_placeholder_LoginRequestCredential(a.(*LoginRequestCredential), b.(*placeholder.LoginRequestCredential), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*placeholder.LoginRequestCredential)(nil), (*LoginRequestCredential)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_placeholder_LoginRequestCredential_To_v1alpha1_LoginRequestCredential(a.(*placeholder.LoginRequestCredential), b.(*LoginRequestCredential), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*LoginRequestList)(nil), (*placeholder.LoginRequestList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_LoginRequestList_To_placeholder_LoginRequestList(a.(*LoginRequestList), b.(*placeholder.LoginRequestList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*placeholder.LoginRequestList)(nil), (*LoginRequestList)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_placeholder_LoginRequestList_To_v1alpha1_LoginRequestList(a.(*placeholder.LoginRequestList), b.(*LoginRequestList), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*LoginRequestSpec)(nil), (*placeholder.LoginRequestSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_LoginRequestSpec_To_placeholder_LoginRequestSpec(a.(*LoginRequestSpec), b.(*placeholder.LoginRequestSpec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*placeholder.LoginRequestSpec)(nil), (*LoginRequestSpec)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_placeholder_LoginRequestSpec_To_v1alpha1_LoginRequestSpec(a.(*placeholder.LoginRequestSpec), b.(*LoginRequestSpec), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*LoginRequestStatus)(nil), (*placeholder.LoginRequestStatus)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_LoginRequestStatus_To_placeholder_LoginRequestStatus(a.(*LoginRequestStatus), b.(*placeholder.LoginRequestStatus), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*placeholder.LoginRequestStatus)(nil), (*LoginRequestStatus)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_placeholder_LoginRequestStatus_To_v1alpha1_LoginRequestStatus(a.(*placeholder.LoginRequestStatus), b.(*LoginRequestStatus), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*LoginRequestTokenCredential)(nil), (*placeholder.LoginRequestTokenCredential)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_LoginRequestTokenCredential_To_placeholder_LoginRequestTokenCredential(a.(*LoginRequestTokenCredential), b.(*placeholder.LoginRequestTokenCredential), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*placeholder.LoginRequestTokenCredential)(nil), (*LoginRequestTokenCredential)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_placeholder_LoginRequestTokenCredential_To_v1alpha1_LoginRequestTokenCredential(a.(*placeholder.LoginRequestTokenCredential), b.(*LoginRequestTokenCredential), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*User)(nil), (*placeholder.User)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_User_To_placeholder_User(a.(*User), b.(*placeholder.User), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*placeholder.User)(nil), (*User)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_placeholder_User_To_v1alpha1_User(a.(*placeholder.User), b.(*User), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v1alpha1_LoginRequest_To_placeholder_LoginRequest(in *LoginRequest, out *placeholder.LoginRequest, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_LoginRequestSpec_To_placeholder_LoginRequestSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	if err := Convert_v1alpha1_LoginRequestStatus_To_placeholder_LoginRequestStatus(&in.Status, &out.Status, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_LoginRequest_To_placeholder_LoginRequest is an autogenerated conversion function.
func Convert_v1alpha1_LoginRequest_To_placeholder_LoginRequest(in *LoginRequest, out *placeholder.LoginRequest, s conversion.Scope) error {
	return autoConvert_v1alpha1_LoginRequest_To_placeholder_LoginRequest(in, out, s)
}

func autoConvert_placeholder_LoginRequest_To_v1alpha1_LoginRequest(in *placeholder.LoginRequest, out *LoginRequest, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_placeholder_LoginRequestSpec_To_v1alpha1_LoginRequestSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	if err := Convert_placeholder_LoginRequestStatus_To_v1alpha1_LoginRequestStatus(&in.Status, &out.Status, s); err != nil {
		return err
	}
	return nil
}

// Convert_placeholder_LoginRequest_To_v1alpha1_LoginRequest is an autogenerated conversion function.
func Convert_placeholder_LoginRequest_To_v1alpha1_LoginRequest(in *placeholder.LoginRequest, out *LoginRequest, s conversion.Scope) error {
	return autoConvert_placeholder_LoginRequest_To_v1alpha1_LoginRequest(in, out, s)
}

func autoConvert_v1alpha1_LoginRequestCredential_To_placeholder_LoginRequestCredential(in *LoginRequestCredential, out *placeholder.LoginRequestCredential, s conversion.Scope) error {
	out.ExpirationTimestamp = in.ExpirationTimestamp
	out.Token = in.Token
	out.ClientCertificateData = in.ClientCertificateData
	out.ClientKeyData = in.ClientKeyData
	return nil
}

// Convert_v1alpha1_LoginRequestCredential_To_placeholder_LoginRequestCredential is an autogenerated conversion function.
func Convert_v1alpha1_LoginRequestCredential_To_placeholder_LoginRequestCredential(in *LoginRequestCredential, out *placeholder.LoginRequestCredential, s conversion.Scope) error {
	return autoConvert_v1alpha1_LoginRequestCredential_To_placeholder_LoginRequestCredential(in, out, s)
}

func autoConvert_placeholder_LoginRequestCredential_To_v1alpha1_LoginRequestCredential(in *placeholder.LoginRequestCredential, out *LoginRequestCredential, s conversion.Scope) error {
	out.ExpirationTimestamp = in.ExpirationTimestamp
	out.Token = in.Token
	out.ClientCertificateData = in.ClientCertificateData
	out.ClientKeyData = in.ClientKeyData
	return nil
}

// Convert_placeholder_LoginRequestCredential_To_v1alpha1_LoginRequestCredential is an autogenerated conversion function.
func Convert_placeholder_LoginRequestCredential_To_v1alpha1_LoginRequestCredential(in *placeholder.LoginRequestCredential, out *LoginRequestCredential, s conversion.Scope) error {
	return autoConvert_placeholder_LoginRequestCredential_To_v1alpha1_LoginRequestCredential(in, out, s)
}

func autoConvert_v1alpha1_LoginRequestList_To_placeholder_LoginRequestList(in *LoginRequestList, out *placeholder.LoginRequestList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]placeholder.LoginRequest)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_v1alpha1_LoginRequestList_To_placeholder_LoginRequestList is an autogenerated conversion function.
func Convert_v1alpha1_LoginRequestList_To_placeholder_LoginRequestList(in *LoginRequestList, out *placeholder.LoginRequestList, s conversion.Scope) error {
	return autoConvert_v1alpha1_LoginRequestList_To_placeholder_LoginRequestList(in, out, s)
}

func autoConvert_placeholder_LoginRequestList_To_v1alpha1_LoginRequestList(in *placeholder.LoginRequestList, out *LoginRequestList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]LoginRequest)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_placeholder_LoginRequestList_To_v1alpha1_LoginRequestList is an autogenerated conversion function.
func Convert_placeholder_LoginRequestList_To_v1alpha1_LoginRequestList(in *placeholder.LoginRequestList, out *LoginRequestList, s conversion.Scope) error {
	return autoConvert_placeholder_LoginRequestList_To_v1alpha1_LoginRequestList(in, out, s)
}

func autoConvert_v1alpha1_LoginRequestSpec_To_placeholder_LoginRequestSpec(in *LoginRequestSpec, out *placeholder.LoginRequestSpec, s conversion.Scope) error {
	out.Type = placeholder.LoginCredentialType(in.Type)
	out.Token = (*placeholder.LoginRequestTokenCredential)(unsafe.Pointer(in.Token))
	return nil
}

// Convert_v1alpha1_LoginRequestSpec_To_placeholder_LoginRequestSpec is an autogenerated conversion function.
func Convert_v1alpha1_LoginRequestSpec_To_placeholder_LoginRequestSpec(in *LoginRequestSpec, out *placeholder.LoginRequestSpec, s conversion.Scope) error {
	return autoConvert_v1alpha1_LoginRequestSpec_To_placeholder_LoginRequestSpec(in, out, s)
}

func autoConvert_placeholder_LoginRequestSpec_To_v1alpha1_LoginRequestSpec(in *placeholder.LoginRequestSpec, out *LoginRequestSpec, s conversion.Scope) error {
	out.Type = LoginCredentialType(in.Type)
	out.Token = (*LoginRequestTokenCredential)(unsafe.Pointer(in.Token))
	return nil
}

// Convert_placeholder_LoginRequestSpec_To_v1alpha1_LoginRequestSpec is an autogenerated conversion function.
func Convert_placeholder_LoginRequestSpec_To_v1alpha1_LoginRequestSpec(in *placeholder.LoginRequestSpec, out *LoginRequestSpec, s conversion.Scope) error {
	return autoConvert_placeholder_LoginRequestSpec_To_v1alpha1_LoginRequestSpec(in, out, s)
}

func autoConvert_v1alpha1_LoginRequestStatus_To_placeholder_LoginRequestStatus(in *LoginRequestStatus, out *placeholder.LoginRequestStatus, s conversion.Scope) error {
	out.Credential = (*placeholder.LoginRequestCredential)(unsafe.Pointer(in.Credential))
	out.User = (*placeholder.User)(unsafe.Pointer(in.User))
	out.Message = in.Message
	return nil
}

// Convert_v1alpha1_LoginRequestStatus_To_placeholder_LoginRequestStatus is an autogenerated conversion function.
func Convert_v1alpha1_LoginRequestStatus_To_placeholder_LoginRequestStatus(in *LoginRequestStatus, out *placeholder.LoginRequestStatus, s conversion.Scope) error {
	return autoConvert_v1alpha1_LoginRequestStatus_To_placeholder_LoginRequestStatus(in, out, s)
}

func autoConvert_placeholder_LoginRequestStatus_To_v1alpha1_LoginRequestStatus(in *placeholder.LoginRequestStatus, out *LoginRequestStatus, s conversion.Scope) error {
	out.Credential = (*LoginRequestCredential)(unsafe.Pointer(in.Credential))
	out.User = (*User)(unsafe.Pointer(in.User))
	out.Message = in.Message
	return nil
}

// Convert_placeholder_LoginRequestStatus_To_v1alpha1_LoginRequestStatus is an autogenerated conversion function.
func Convert_placeholder_LoginRequestStatus_To_v1alpha1_LoginRequestStatus(in *placeholder.LoginRequestStatus, out *LoginRequestStatus, s conversion.Scope) error {
	return autoConvert_placeholder_LoginRequestStatus_To_v1alpha1_LoginRequestStatus(in, out, s)
}

func autoConvert_v1alpha1_LoginRequestTokenCredential_To_placeholder_LoginRequestTokenCredential(in *LoginRequestTokenCredential, out *placeholder.LoginRequestTokenCredential, s conversion.Scope) error {
	out.Value = in.Value
	return nil
}

// Convert_v1alpha1_LoginRequestTokenCredential_To_placeholder_LoginRequestTokenCredential is an autogenerated conversion function.
func Convert_v1alpha1_LoginRequestTokenCredential_To_placeholder_LoginRequestTokenCredential(in *LoginRequestTokenCredential, out *placeholder.LoginRequestTokenCredential, s conversion.Scope) error {
	return autoConvert_v1alpha1_LoginRequestTokenCredential_To_placeholder_LoginRequestTokenCredential(in, out, s)
}

func autoConvert_placeholder_LoginRequestTokenCredential_To_v1alpha1_LoginRequestTokenCredential(in *placeholder.LoginRequestTokenCredential, out *LoginRequestTokenCredential, s conversion.Scope) error {
	out.Value = in.Value
	return nil
}

// Convert_placeholder_LoginRequestTokenCredential_To_v1alpha1_LoginRequestTokenCredential is an autogenerated conversion function.
func Convert_placeholder_LoginRequestTokenCredential_To_v1alpha1_LoginRequestTokenCredential(in *placeholder.LoginRequestTokenCredential, out *LoginRequestTokenCredential, s conversion.Scope) error {
	return autoConvert_placeholder_LoginRequestTokenCredential_To_v1alpha1_LoginRequestTokenCredential(in, out, s)
}

func autoConvert_v1alpha1_User_To_placeholder_User(in *User, out *placeholder.User, s conversion.Scope) error {
	out.Name = in.Name
	out.Groups = *(*[]string)(unsafe.Pointer(&in.Groups))
	return nil
}

// Convert_v1alpha1_User_To_placeholder_User is an autogenerated conversion function.
func Convert_v1alpha1_User_To_placeholder_User(in *User, out *placeholder.User, s conversion.Scope) error {
	return autoConvert_v1alpha1_User_To_placeholder_User(in, out, s)
}

func autoConvert_placeholder_User_To_v1alpha1_User(in *placeholder.User, out *User, s conversion.Scope) error {
	out.Name = in.Name
	out.Groups = *(*[]string)(unsafe.Pointer(&in.Groups))
	return nil
}

// Convert_placeholder_User_To_v1alpha1_User is an autogenerated conversion function.
func Convert_placeholder_User_To_v1alpha1_User(in *placeholder.User, out *User, s conversion.Scope) error {
	return autoConvert_placeholder_User_To_v1alpha1_User(in, out, s)
}
