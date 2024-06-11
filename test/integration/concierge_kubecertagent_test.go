// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	conciergeconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	"go.pinniped.dev/test/testlib"
)

func TestKubeCertAgent(t *testing.T) {
	env := testlib.IntegrationEnv(t).WithCapability(testlib.ClusterSigningKeyIsAvailable)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kubeClient := testlib.NewKubernetesClientset(t)
	adminConciergeClient := testlib.NewConciergeClientset(t)

	// Expect there to be at least on healthy kube-cert-agent pod on this cluster.
	testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		agentPods, err := kubeClient.CoreV1().Pods(env.ConciergeNamespace).List(ctx, metav1.ListOptions{
			LabelSelector: "kube-cert-agent.pinniped.dev=v3",
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
	testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		credentialIssuer, err := adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Get(ctx, credentialIssuerName(env), metav1.GetOptions{})
		if err != nil {
			t.Logf("could not get the CredentialIssuer: %v", err)
			return false, nil
		}

		// If there's no successful strategy yet, wait until there is.
		strategy := findSuccessfulStrategy(credentialIssuer, conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType)
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
		if strategy.Frontend.Type != conciergeconfigv1alpha1.TokenCredentialRequestAPIFrontendType {
			return false, fmt.Errorf("strategy had unexpected frontend type %q", strategy.Frontend.Type)
		}
		return true, nil
	}, 3*time.Minute, 2*time.Second)
}

func findSuccessfulStrategy(credentialIssuer *conciergeconfigv1alpha1.CredentialIssuer, strategyType conciergeconfigv1alpha1.StrategyType) *conciergeconfigv1alpha1.CredentialIssuerStrategy {
	for _, strategy := range credentialIssuer.Status.Strategies {
		if strategy.Type != strategyType {
			continue
		}
		if strategy.Status != conciergeconfigv1alpha1.SuccessStrategyStatus {
			continue
		}
		return &strategy
	}
	return nil
}

// safe to run in parallel with serial tests since it only interacts with a test local pod, see main_test.go.
func TestLegacyPodCleaner_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t).WithCapability(testlib.ClusterSigningKeyIsAvailable)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	kubeClient := testlib.NewKubernetesClientset(t)

	// Pick the same labels that the legacy code would have used to run the kube-cert-agent pod.
	legacyAgentLabels := map[string]string{}
	for k, v := range env.ConciergeCustomLabels {
		legacyAgentLabels[k] = v
	}
	legacyAgentLabels["app"] = env.ConciergeAppName
	legacyAgentLabels["kube-cert-agent.pinniped.dev"] = "true"
	legacyAgentLabels["pinniped.dev/test"] = ""

	// Deploy a fake legacy agent pod using those labels.
	pod, err := kubeClient.CoreV1().Pods(env.ConciergeNamespace).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-legacy-kube-cert-agent-",
			Labels:       legacyAgentLabels,
			Annotations:  map[string]string{"pinniped.dev/testName": t.Name()},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "sleeper",
				Image:           env.ShellContainerImage,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         []string{"/bin/sleep", "infinity"},
			}},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err, "failed to create fake legacy agent pod")
	t.Logf("deployed fake legacy agent pod %s/%s with labels %s", pod.Namespace, pod.Name, labels.SelectorFromSet(legacyAgentLabels).String())

	// No matter what happens, clean up the agent pod at the end of the test (normally it will already have been deleted).
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		err := kubeClient.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)})
		if !apierrors.IsNotFound(err) {
			require.NoError(t, err, "failed to clean up fake legacy agent pod")
		}
	})

	// Expect the legacy-pod-cleaner controller to delete the pod.
	testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
		_, err := kubeClient.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			t.Logf("fake legacy agent pod %s/%s was deleted as expected", pod.Namespace, pod.Name)
			return true, nil
		}
		return false, err
	}, 2*time.Minute, 1*time.Second)
}
