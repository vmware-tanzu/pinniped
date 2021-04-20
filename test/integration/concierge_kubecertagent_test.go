// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	conciergev1alpha "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	"go.pinniped.dev/test/library"
)

func TestKubeCertAgent(t *testing.T) {
	env := library.IntegrationEnv(t).WithCapability(library.ClusterSigningKeyIsAvailable)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kubeClient := library.NewKubernetesClientset(t)
	adminConciergeClient := library.NewConciergeClientset(t)

	// Expect there to be at least on healthy kube-cert-agent pod on this cluster.
	library.RequireEventuallyWithoutError(t, func() (bool, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		agentPods, err := kubeClient.CoreV1().Pods(env.ConciergeNamespace).List(ctx, metav1.ListOptions{
			LabelSelector: "kube-cert-agent.pinniped.dev=v2",
		})
		if err != nil {
			return false, fmt.Errorf("failed to list pods: %w", err)
		}
		for _, p := range agentPods.Items {
			t.Logf("found agent pod %s/%s in phase %s", p.Namespace, p.Name, p.Status.Phase)
		}

		for _, p := range agentPods.Items {
			if p.Status.Phase == corev1.PodRunning {
				return true, nil
			}
		}
		return false, nil
	}, 1*time.Minute, 2*time.Second, "never saw a healthy kube-cert-agent Pod running")

	// Expect that the CredentialIssuer will have a healthy KubeClusterSigningCertificate strategy.
	library.RequireEventuallyWithoutError(t, func() (bool, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		credentialIssuer, err := adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Get(ctx, credentialIssuerName(env), metav1.GetOptions{})
		if err != nil {
			t.Logf("could not get the CredentialIssuer: %v", err)
			return false, nil
		}

		// If there's no successful strategy yet, wait until there is.
		strategy := findSuccessfulStrategy(credentialIssuer, conciergev1alpha.KubeClusterSigningCertificateStrategyType)
		if strategy == nil {
			t.Log("could not find a successful TokenCredentialRequestAPI strategy in the CredentialIssuer:")
			for _, s := range credentialIssuer.Status.Strategies {
				t.Logf("  strategy %s has status %s/%s: %s", s.Type, s.Status, s.Reason, s.Message)
			}
			return false, nil
		}

		// The successful strategy must have a frontend of type TokenCredentialRequestAPI.
		if strategy.Frontend == nil {
			return false, fmt.Errorf("strategy did not find a Frontend")
		}
		if strategy.Frontend.Type != conciergev1alpha.TokenCredentialRequestAPIFrontendType {
			return false, fmt.Errorf("strategy had unexpected frontend type %q", strategy.Frontend.Type)
		}
		return true, nil
	}, 3*time.Minute, 2*time.Second)
}

func findSuccessfulStrategy(credentialIssuer *conciergev1alpha.CredentialIssuer, strategyType conciergev1alpha.StrategyType) *conciergev1alpha.CredentialIssuerStrategy {
	for _, strategy := range credentialIssuer.Status.Strategies {
		if strategy.Type != strategyType {
			continue
		}
		if strategy.Status != conciergev1alpha.SuccessStrategyStatus {
			continue
		}
		return &strategy
	}
	return nil
}
