/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/suzerain-io/placeholder-name/test/library"
)

func TestAppAvailability(t *testing.T) {
	library.SkipUnlessIntegration(t)
	namespaceName := library.Getenv(t, "PLACEHOLDER_NAME_NAMESPACE")
	daemonSetName := library.Getenv(t, "PLACEHOLDER_NAME_APP_NAME")

	client := library.NewClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	daemonSet, err := client.AppsV1().DaemonSets(namespaceName).Get(ctx, daemonSetName, metav1.GetOptions{})
	require.NoError(t, err)

	require.GreaterOrEqual(t, daemonSet.Status.NumberAvailable, int32(1))
}
