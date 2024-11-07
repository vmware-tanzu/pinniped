// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	kubefake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"

	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
)

func TestLegacyPodCleanerController(t *testing.T) {
	t.Parallel()

	legacyAgentPodWithoutExtraLabel := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "concierge",
			Name:            "pinniped-concierge-kube-cert-agent-without-extra-label",
			Labels:          map[string]string{"kube-cert-agent.pinniped.dev": "true"},
			UID:             "1",
			ResourceVersion: "2",
		},
		Spec:   corev1.PodSpec{},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	legacyAgentPodWithExtraLabel := legacyAgentPodWithoutExtraLabel.DeepCopy()
	legacyAgentPodWithExtraLabel.Name = "pinniped-concierge-kube-cert-agent-with-extra-label"
	legacyAgentPodWithExtraLabel.Labels["extralabel"] = "labelvalue"
	legacyAgentPodWithExtraLabel.Labels["anotherextralabel"] = "labelvalue"
	legacyAgentPodWithExtraLabel.UID = "3"
	legacyAgentPodWithExtraLabel.ResourceVersion = "4"

	nonLegacyAgentPod := legacyAgentPodWithExtraLabel.DeepCopy()
	nonLegacyAgentPod.Name = "pinniped-concierge-kube-cert-agent-not-legacy"
	nonLegacyAgentPod.Labels["kube-cert-agent.pinniped.dev"] = "v2"
	nonLegacyAgentPod.UID = "5"
	nonLegacyAgentPod.ResourceVersion = "6"

	tests := []struct {
		name               string
		kubeObjects        []runtime.Object
		addKubeReactions   func(*kubefake.Clientset)
		wantDistinctErrors []string
		wantDistinctLogs   []string
		wantActions        []coretesting.Action
	}{
		{
			name:        "no pods",
			wantActions: []coretesting.Action{},
		},
		{
			name: "mix of pods",
			kubeObjects: []runtime.Object{
				legacyAgentPodWithoutExtraLabel, // should not be delete (missing extra label)
				legacyAgentPodWithExtraLabel,    // should be deleted
				nonLegacyAgentPod,               // should not be deleted (missing legacy agent label)
			},
			wantDistinctErrors: []string{""},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"legacy-pod-cleaner-controller","caller":"kubecertagent/legacypodcleaner.go:<line>$kubecertagent.NewLegacyPodCleanerController.func1","message":"deleted legacy kube-cert-agent pod","pod":{"name":"pinniped-concierge-kube-cert-agent-with-extra-label","namespace":"concierge"}}`,
			},
			wantActions: []coretesting.Action{ // the first delete triggers the informer again, but the second invocation triggers a Not Found
				coretesting.NewGetAction(corev1.Resource("pods").WithVersion("v1"), "concierge", legacyAgentPodWithExtraLabel.Name),
				coretesting.NewDeleteActionWithOptions(corev1.Resource("pods").WithVersion("v1"), "concierge", legacyAgentPodWithExtraLabel.Name, testutil.NewPreconditions("3", "4")),
				coretesting.NewGetAction(corev1.Resource("pods").WithVersion("v1"), "concierge", legacyAgentPodWithExtraLabel.Name),
			},
		},
		{
			name: "fail to delete",
			kubeObjects: []runtime.Object{
				legacyAgentPodWithoutExtraLabel, // should not be delete (missing extra label)
				legacyAgentPodWithExtraLabel,    // should be deleted
				nonLegacyAgentPod,               // should not be deleted (missing legacy agent label)
			},
			addKubeReactions: func(clientset *kubefake.Clientset) {
				clientset.PrependReactor("delete", "*", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("some delete error")
				})
			},
			wantDistinctErrors: []string{
				"could not delete legacy agent pod: some delete error",
			},
			wantActions: []coretesting.Action{
				coretesting.NewGetAction(corev1.Resource("pods").WithVersion("v1"), "concierge", legacyAgentPodWithExtraLabel.Name),
				coretesting.NewDeleteActionWithOptions(corev1.Resource("pods").WithVersion("v1"), "concierge", legacyAgentPodWithExtraLabel.Name, testutil.NewPreconditions("3", "4")),
				coretesting.NewGetAction(corev1.Resource("pods").WithVersion("v1"), "concierge", legacyAgentPodWithExtraLabel.Name),
				coretesting.NewDeleteActionWithOptions(corev1.Resource("pods").WithVersion("v1"), "concierge", legacyAgentPodWithExtraLabel.Name, testutil.NewPreconditions("3", "4")),
			},
		},
		{
			name: "fail to delete because of not found error",
			kubeObjects: []runtime.Object{
				legacyAgentPodWithoutExtraLabel, // should not be delete (missing extra label)
				legacyAgentPodWithExtraLabel,    // should be deleted
				nonLegacyAgentPod,               // should not be deleted (missing legacy agent label)
			},
			addKubeReactions: func(clientset *kubefake.Clientset) {
				clientset.PrependReactor("delete", "*", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, apierrors.NewNotFound(action.GetResource().GroupResource(), "")
				})
			},
			wantDistinctErrors: []string{""},
			wantActions: []coretesting.Action{
				coretesting.NewGetAction(corev1.Resource("pods").WithVersion("v1"), "concierge", legacyAgentPodWithExtraLabel.Name),
				coretesting.NewDeleteActionWithOptions(corev1.Resource("pods").WithVersion("v1"), "concierge", legacyAgentPodWithExtraLabel.Name, testutil.NewPreconditions("3", "4")),
			},
		},
		{
			name: "fail to delete because of not found error on get",
			kubeObjects: []runtime.Object{
				legacyAgentPodWithoutExtraLabel, // should not be delete (missing extra label)
				legacyAgentPodWithExtraLabel,    // should be deleted
				nonLegacyAgentPod,               // should not be deleted (missing legacy agent label)
			},
			addKubeReactions: func(clientset *kubefake.Clientset) {
				clientset.PrependReactor("get", "*", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, apierrors.NewNotFound(action.GetResource().GroupResource(), "")
				})
			},
			wantDistinctErrors: []string{""},
			wantActions: []coretesting.Action{
				coretesting.NewGetAction(corev1.Resource("pods").WithVersion("v1"), "concierge", legacyAgentPodWithExtraLabel.Name),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kubeClientset := kubefake.NewSimpleClientset(tt.kubeObjects...)
			if tt.addKubeReactions != nil {
				tt.addKubeReactions(kubeClientset)
			}

			kubeInformers := informers.NewSharedInformerFactory(kubeClientset, 0)
			logger, log := plog.TestLogger(t)
			controller := NewLegacyPodCleanerController(
				AgentConfig{
					Namespace: "concierge",
					Labels:    map[string]string{"extralabel": "labelvalue"},
				},
				&kubeclient.Client{Kubernetes: kubeClientset},
				kubeInformers.Core().V1().Pods(),
				logger,
			)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			errorMessages := runControllerUntilQuiet(ctx, t, controller, func(_ context.Context, _ *testing.T) {}, kubeInformers)
			assert.Equal(t, tt.wantDistinctErrors, deduplicate(errorMessages), "unexpected errors")
			assert.Equal(t, tt.wantDistinctLogs, deduplicate(testutil.SplitByNewline(log.String())), "unexpected logs")
			assert.Equal(t, tt.wantActions, kubeClientset.Actions()[2:], "unexpected actions")
		})
	}
}
