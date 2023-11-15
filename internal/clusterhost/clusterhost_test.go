// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package clusterhost

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
)

func TestHasControlPlaneNodes(t *testing.T) {
	tests := []struct {
		name            string
		nodes           []*corev1.Node
		listNodesErr    error
		wantErr         error
		wantReturnValue bool
	}{
		{
			name:         "Fetching nodes returns an error",
			listNodesErr: errors.New("couldn't get nodes"),
			wantErr:      errors.New("error fetching nodes: couldn't get nodes"),
		},
		{
			name:    "Fetching nodes returns an empty array",
			nodes:   []*corev1.Node{},
			wantErr: errors.New("no nodes found"),
		},
		{
			name: "Nodes found, but not control plane nodes",
			nodes: []*corev1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
						Labels: map[string]string{
							"not-control-plane-label": "some-value",
							"kubernetes.io/node-role": "worker",
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node-2",
						Labels: map[string]string{"node-role.kubernetes.io/worker": ""},
					},
				},
			},
			wantReturnValue: false,
		},
		{
			name: "Nodes found, including a control-plane role in node-role.kubernetes.io/<role> format",
			nodes: []*corev1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node-1",
						Labels: map[string]string{"unrelated-label": "some-value"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-2",
						Labels: map[string]string{
							"some-other-label":                      "some-value",
							"node-role.kubernetes.io/control-plane": "",
						},
					},
				},
			},
			wantReturnValue: true,
		},
		{
			name: "Nodes found, including a master role in node-role.kubernetes.io/<role> format",
			nodes: []*corev1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node-1",
						Labels: map[string]string{"unrelated-label": "some-value"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-2",
						Labels: map[string]string{
							"some-other-label":               "some-value",
							"node-role.kubernetes.io/master": "",
						},
					},
				},
			},
			wantReturnValue: true,
		},
		{
			name: "Nodes found, including a control-plane role in kubernetes.io/node-role=<role> format",
			nodes: []*corev1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node-1",
						Labels: map[string]string{"unrelated-label": "some-value"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-2",
						Labels: map[string]string{
							"some-other-label":        "some-value",
							"kubernetes.io/node-role": "control-plane",
						},
					},
				},
			},
			wantReturnValue: true,
		},
		{
			name: "Nodes found, including a master role in kubernetes.io/node-role=<role> format",
			nodes: []*corev1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node-1",
						Labels: map[string]string{"unrelated-label": "some-value"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-2",
						Labels: map[string]string{
							"some-other-label":        "some-value",
							"kubernetes.io/node-role": "master",
						},
					},
				},
			},
			wantReturnValue: true,
		},
	}
	for _, tt := range tests {
		test := tt
		t.Run(test.name, func(t *testing.T) {
			kubeClient := kubernetesfake.NewSimpleClientset()
			if test.listNodesErr != nil {
				listNodesErr := test.listNodesErr
				kubeClient.PrependReactor(
					"list",
					"nodes",
					func(_ coretesting.Action) (bool, runtime.Object, error) {
						return true, nil, listNodesErr
					},
				)
			}
			for _, node := range test.nodes {
				err := kubeClient.Tracker().Add(node)
				require.NoError(t, err)
			}
			clusterHost := New(kubeClient)
			hasControlPlaneNodes, err := clusterHost.HasControlPlaneNodes(context.Background())
			require.Equal(t, test.wantErr, err)
			require.Equal(t, test.wantReturnValue, hasControlPlaneNodes)
		})
	}
}
