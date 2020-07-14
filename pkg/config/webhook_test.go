/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"
)

func TestAnonymousKubeconfig(t *testing.T) {
	expect := require.New(t)

	f, err := ioutil.TempFile("", "placeholder-name-anonymous-kubeconfig-test-*")
	expect.NoError(err)
	defer os.Remove(f.Name())

	err = anonymousKubeconfig("https://tuna.com", []byte("ca bundle"), f)
	expect.NoError(err)

	config, err := clientcmd.BuildConfigFromFlags("", f.Name())
	expect.NoError(err)

	expect.Equal("https://tuna.com", config.Host)
}
