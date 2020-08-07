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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/suzerain-io/placeholder-name/test/library"
)

func TestGetDeployment(t *testing.T) {
	library.SkipUnlessIntegration(t)
	namespaceName := library.Getenv(t, "PLACEHOLDER_NAME_NAMESPACE")
	deploymentName := library.Getenv(t, "PLACEHOLDER_NAME_DEPLOYMENT")

	client := library.NewClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	appDeployment, err := client.AppsV1().Deployments(namespaceName).Get(ctx, deploymentName, metav1.GetOptions{})
	require.NoError(t, err)

	cond := library.GetDeploymentCondition(appDeployment.Status, appsv1.DeploymentAvailable)
	require.NotNil(t, cond)
	require.Equalf(t, corev1.ConditionTrue, cond.Status, "app should be available: %s", library.Sdump(appDeployment))
}
