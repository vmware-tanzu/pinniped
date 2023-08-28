// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package clusterhost

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	labelNodeRolePrefix  = "node-role.kubernetes.io/"
	nodeLabelRole        = "kubernetes.io/node-role"
	controlPlaneNodeRole = "control-plane"
	// This role was deprecated by Kubernetes 1.20.
	// https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.20.md#urgent-upgrade-notes
	// This role will be removed in Kubernetes 1.24
	// https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.24.md#urgent-upgrade-notes
	masterNodeRole = "master"
)

type ClusterHost struct {
	client kubernetes.Interface
}

func New(client kubernetes.Interface) *ClusterHost {
	return &ClusterHost{client: client}
}

func (c *ClusterHost) HasControlPlaneNodes(ctx context.Context) (bool, error) {
	nodes, err := c.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("error fetching nodes: %v", err)
	}
	if len(nodes.Items) == 0 {
		return false, fmt.Errorf("no nodes found")
	}
	for _, node := range nodes.Items {
		for k, v := range node.Labels {
			if isControlPlaneNodeRole(k, v) {
				return true, nil
			}
		}
	}

	return false, nil
}

func isControlPlaneNodeRole(k string, v string) bool {
	if k == labelNodeRolePrefix+controlPlaneNodeRole {
		return true
	}
	if k == labelNodeRolePrefix+masterNodeRole {
		return true
	}
	if k == nodeLabelRole && v == controlPlaneNodeRole {
		return true
	}
	if k == nodeLabelRole && v == masterNodeRole {
		return true
	}
	return false
}
