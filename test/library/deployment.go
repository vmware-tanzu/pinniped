/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package library

import appsv1 "k8s.io/api/apps/v1"

// GetDeploymentCondition returns the condition with the provided type.
// Copied from k8s.io/kubectl/pkg/util/deployment/deployment.go to prevent us from vendoring the world.
func GetDeploymentCondition(status appsv1.DeploymentStatus, condType appsv1.DeploymentConditionType) *appsv1.DeploymentCondition {
	for i := range status.Conditions {
		c := status.Conditions[i]
		if c.Type == condType {
			return &c
		}
	}
	return nil
}
