// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	loginapi "go.pinniped.dev/generated/1.20/apis/concierge/login"
	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
)

const knownGoodUsage = `
pinniped-concierge provides a generic API for mapping an external
credential from somewhere to an internal credential to be used for
authenticating to the Kubernetes API.

Usage:
  pinniped-concierge [flags]

Flags:
  -c, --config string              path to configuration file (default "pinniped.yaml")
      --downward-api-path string   path to Downward API volume mount (default "/etc/podinfo")
  -h, --help                       help for pinniped-concierge
`

func TestCommand(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantErr    string
		wantStdout string
	}{
		{
			name: "NoArgsSucceeds",
			args: []string{},
		},
		{
			name:       "Usage",
			args:       []string{"-h"},
			wantStdout: knownGoodUsage,
		},
		{
			name:    "OneArgFails",
			args:    []string{"tuna"},
			wantErr: `unknown command "tuna" for "pinniped-concierge"`,
		},
		{
			name: "ShortConfigFlagSucceeds",
			args: []string{"-c", "some/path/to/config.yaml"},
		},
		{
			name: "LongConfigFlagSucceeds",
			args: []string{"--config", "some/path/to/config.yaml"},
		},
		{
			name: "OneArgWithConfigFlagFails",
			args: []string{
				"--config", "some/path/to/config.yaml",
				"tuna",
			},
			wantErr: `unknown command "tuna" for "pinniped-concierge"`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			stdout := bytes.NewBuffer([]byte{})
			stderr := bytes.NewBuffer([]byte{})

			a := New(context.Background(), test.args, stdout, stderr)
			a.cmd.RunE = func(cmd *cobra.Command, args []string) error {
				return nil
			}
			err := a.Run()
			if test.wantErr != "" {
				require.EqualError(t, err, test.wantErr)
			} else {
				require.NoError(t, err)
			}
			if test.wantStdout != "" {
				require.Equal(t, strings.TrimSpace(test.wantStdout), strings.TrimSpace(stdout.String()), cmp.Diff(test.wantStdout, stdout.String()))
			}
		})
	}
}

func Test_getAggregatedAPIServerScheme(t *testing.T) {
	// the standard group
	regularGV := schema.GroupVersion{
		Group:   "login.concierge.pinniped.dev",
		Version: "v1alpha1",
	}
	regularGVInternal := schema.GroupVersion{
		Group:   "login.concierge.pinniped.dev",
		Version: runtime.APIVersionInternal,
	}

	// the canonical other group
	otherGV := schema.GroupVersion{
		Group:   "login.concierge.walrus.tld",
		Version: "v1alpha1",
	}
	otherGVInternal := schema.GroupVersion{
		Group:   "login.concierge.walrus.tld",
		Version: runtime.APIVersionInternal,
	}

	// kube's core internal
	internalGV := schema.GroupVersion{
		Group:   "",
		Version: runtime.APIVersionInternal,
	}

	tests := []struct {
		name     string
		apiGroup string
		want     map[schema.GroupVersionKind]reflect.Type
	}{
		{
			name:     "regular api group",
			apiGroup: "login.concierge.pinniped.dev",
			want: map[schema.GroupVersionKind]reflect.Type{
				// all the types that are in the aggregated API group

				regularGV.WithKind("TokenCredentialRequest"):     reflect.TypeOf(&loginv1alpha1.TokenCredentialRequest{}).Elem(),
				regularGV.WithKind("TokenCredentialRequestList"): reflect.TypeOf(&loginv1alpha1.TokenCredentialRequestList{}).Elem(),

				regularGVInternal.WithKind("TokenCredentialRequest"):     reflect.TypeOf(&loginapi.TokenCredentialRequest{}).Elem(),
				regularGVInternal.WithKind("TokenCredentialRequestList"): reflect.TypeOf(&loginapi.TokenCredentialRequestList{}).Elem(),

				regularGV.WithKind("CreateOptions"): reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				regularGV.WithKind("DeleteOptions"): reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				regularGV.WithKind("ExportOptions"): reflect.TypeOf(&metav1.ExportOptions{}).Elem(),
				regularGV.WithKind("GetOptions"):    reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				regularGV.WithKind("ListOptions"):   reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				regularGV.WithKind("PatchOptions"):  reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				regularGV.WithKind("UpdateOptions"): reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				regularGV.WithKind("WatchEvent"):    reflect.TypeOf(&metav1.WatchEvent{}).Elem(),

				regularGVInternal.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				// the types below this line do not really matter to us because they are in the core group

				internalGV.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				metav1.Unversioned.WithKind("APIGroup"):        reflect.TypeOf(&metav1.APIGroup{}).Elem(),
				metav1.Unversioned.WithKind("APIGroupList"):    reflect.TypeOf(&metav1.APIGroupList{}).Elem(),
				metav1.Unversioned.WithKind("APIResourceList"): reflect.TypeOf(&metav1.APIResourceList{}).Elem(),
				metav1.Unversioned.WithKind("APIVersions"):     reflect.TypeOf(&metav1.APIVersions{}).Elem(),
				metav1.Unversioned.WithKind("CreateOptions"):   reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				metav1.Unversioned.WithKind("DeleteOptions"):   reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				metav1.Unversioned.WithKind("ExportOptions"):   reflect.TypeOf(&metav1.ExportOptions{}).Elem(),
				metav1.Unversioned.WithKind("GetOptions"):      reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				metav1.Unversioned.WithKind("ListOptions"):     reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				metav1.Unversioned.WithKind("PatchOptions"):    reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				metav1.Unversioned.WithKind("Status"):          reflect.TypeOf(&metav1.Status{}).Elem(),
				metav1.Unversioned.WithKind("UpdateOptions"):   reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				metav1.Unversioned.WithKind("WatchEvent"):      reflect.TypeOf(&metav1.WatchEvent{}).Elem(),
			},
		},
		{
			name:     "other api group",
			apiGroup: "login.concierge.walrus.tld",
			want: map[schema.GroupVersionKind]reflect.Type{
				// all the types that are in the aggregated API group

				otherGV.WithKind("TokenCredentialRequest"):     reflect.TypeOf(&loginv1alpha1.TokenCredentialRequest{}).Elem(),
				otherGV.WithKind("TokenCredentialRequestList"): reflect.TypeOf(&loginv1alpha1.TokenCredentialRequestList{}).Elem(),

				otherGVInternal.WithKind("TokenCredentialRequest"):     reflect.TypeOf(&loginapi.TokenCredentialRequest{}).Elem(),
				otherGVInternal.WithKind("TokenCredentialRequestList"): reflect.TypeOf(&loginapi.TokenCredentialRequestList{}).Elem(),

				otherGV.WithKind("CreateOptions"): reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				otherGV.WithKind("DeleteOptions"): reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				otherGV.WithKind("ExportOptions"): reflect.TypeOf(&metav1.ExportOptions{}).Elem(),
				otherGV.WithKind("GetOptions"):    reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				otherGV.WithKind("ListOptions"):   reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				otherGV.WithKind("PatchOptions"):  reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				otherGV.WithKind("UpdateOptions"): reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				otherGV.WithKind("WatchEvent"):    reflect.TypeOf(&metav1.WatchEvent{}).Elem(),

				otherGVInternal.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				// the types below this line do not really matter to us because they are in the core group

				internalGV.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				metav1.Unversioned.WithKind("APIGroup"):        reflect.TypeOf(&metav1.APIGroup{}).Elem(),
				metav1.Unversioned.WithKind("APIGroupList"):    reflect.TypeOf(&metav1.APIGroupList{}).Elem(),
				metav1.Unversioned.WithKind("APIResourceList"): reflect.TypeOf(&metav1.APIResourceList{}).Elem(),
				metav1.Unversioned.WithKind("APIVersions"):     reflect.TypeOf(&metav1.APIVersions{}).Elem(),
				metav1.Unversioned.WithKind("CreateOptions"):   reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				metav1.Unversioned.WithKind("DeleteOptions"):   reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				metav1.Unversioned.WithKind("ExportOptions"):   reflect.TypeOf(&metav1.ExportOptions{}).Elem(),
				metav1.Unversioned.WithKind("GetOptions"):      reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				metav1.Unversioned.WithKind("ListOptions"):     reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				metav1.Unversioned.WithKind("PatchOptions"):    reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				metav1.Unversioned.WithKind("Status"):          reflect.TypeOf(&metav1.Status{}).Elem(),
				metav1.Unversioned.WithKind("UpdateOptions"):   reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				metav1.Unversioned.WithKind("WatchEvent"):      reflect.TypeOf(&metav1.WatchEvent{}).Elem(),
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			scheme := getAggregatedAPIServerScheme(tt.apiGroup)
			require.Equal(t, tt.want, scheme.AllKnownTypes())
		})
	}
}
