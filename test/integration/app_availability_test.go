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

	"github.com/suzerain-io/pinniped/test/library"
)

func TestGetDeployment(t *testing.T) {
	library.SkipUnlessIntegration(t)
	library.SkipUnlessClusterHasCapability(t, library.ClusterSigningKeyIsAvailable)
	namespaceName := library.GetEnv(t, "PINNIPED_NAMESPACE")
	deploymentName := library.GetEnv(t, "PINNIPED_APP_NAME")

	client := library.NewClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	appDeployment, err := client.AppsV1().Deployments(namespaceName).Get(ctx, deploymentName, metav1.GetOptions{})
	require.NoError(t, err)

	cond := getDeploymentCondition(appDeployment.Status, appsv1.DeploymentAvailable)
	require.NotNil(t, cond)
	require.Equalf(t, corev1.ConditionTrue, cond.Status, "app should be available: %s", library.Sdump(appDeployment))
}

// getDeploymentCondition returns the condition with the provided type.
// Copied from k8s.io/kubectl/pkg/util/deployment/deployment.go to prevent us from vendoring the world.
func getDeploymentCondition(status appsv1.DeploymentStatus, condType appsv1.DeploymentConditionType) *appsv1.DeploymentCondition {
	for i := range status.Conditions {
		c := status.Conditions[i]
		if c.Type == condType {
			return &c
		}
	}
	return nil
}
