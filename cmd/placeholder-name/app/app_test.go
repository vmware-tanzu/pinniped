/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1fake "k8s.io/client-go/kubernetes/fake"
	aggregationv1fake "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
)

const knownGoodUsage = `
placeholder-name provides a generic API for mapping an external
credential from somewhere to an internal credential to be used for
authenticating to the Kubernetes API.

Usage:
  placeholder-name [flags]

Flags:
  -c, --config string              path to configuration file (default "placeholder-name.yaml")
      --downward-api-path string   path to Downward API volume mount (default "/etc/podinfo")
  -h, --help                       help for placeholder-name
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
			wantErr: `unknown command "tuna" for "placeholder-name"`,
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
			wantErr: `unknown command "tuna" for "placeholder-name"`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			stdout := bytes.NewBuffer([]byte{})
			stderr := bytes.NewBuffer([]byte{})

			a := New(test.args, stdout, stderr)
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
				require.Equal(t, strings.TrimSpace(test.wantStdout), strings.TrimSpace(stdout.String()))
			}
		})
	}
}

func TestServeApp(t *testing.T) {
	t.Parallel()

	fakev1 := corev1fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}})
	fakeaggregationv1 := aggregationv1fake.NewSimpleClientset()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		cancel()

		a := App{
			healthAddr:      "127.0.0.1:0",
			mainAddr:        "127.0.0.1:8443",
			configPath:      "testdata/valid-config.yaml",
			downwardAPIPath: "testdata/podinfo",
		}
		err := a.serve(ctx, fakev1.CoreV1(), fakeaggregationv1)
		require.NoError(t, err)
	})

	t.Run("failure", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		a := App{
			healthAddr:      "127.0.0.1:8081",
			mainAddr:        "127.0.0.1:8081",
			configPath:      "testdata/valid-config.yaml",
			downwardAPIPath: "testdata/podinfo",
		}
		err := a.serve(ctx, fakev1.CoreV1(), fakeaggregationv1)
		require.EqualError(t, err, "listen tcp 127.0.0.1:8081: bind: address already in use")
	})
}
