// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	kubefake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	conciergeconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	conciergefake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	conciergeinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions"
	"go.pinniped.dev/internal/controllerinit"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/kubeclient"
	mocks "go.pinniped.dev/internal/mocks/mockkubecertagent"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/test/testlib"
)

func TestAgentController(t *testing.T) {
	t.Parallel()
	now := time.Date(2021, 4, 13, 9, 57, 0, 0, time.UTC)

	initialCredentialIssuer := &conciergeconfigv1alpha1.CredentialIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: "pinniped-concierge-config"},
	}

	healthyKubeControllerManagerPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "kube-system",
			Name:              "kube-controller-manager-1",
			Labels:            map[string]string{"component": "kube-controller-manager"},
			CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "kube-controller-manager",
				Image: "kubernetes/kube-controller-manager",
				Command: []string{
					"kube-controller-manager",
					"--some-flag",
					"--some-other-flag",
					"--cluster-signing-cert-file", "/path/to/signing.crt",
					"--cluster-signing-key-file=/path/to/signing.key",
					"some arguments here",
					"--and-another-flag",
				},
				VolumeMounts: []corev1.VolumeMount{{
					Name:      "test-volume",
					ReadOnly:  true,
					MountPath: "/path",
				}},
			}},
			Volumes: []corev1.Volume{{
				Name: "test-volume",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/host/path",
					},
				},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	healthyAgentDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "concierge",
			Name:      "pinniped-concierge-kube-cert-agent",
			Labels:    map[string]string{"extralabel": "labelvalue", "app": "anything"},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: metav1.SetAsLabelSelector(map[string]string{
				"kube-cert-agent.pinniped.dev": "v3",
			}),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"extralabel":                   "labelvalue",
						"kube-cert-agent.pinniped.dev": "v3",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:    "sleeper",
						Image:   "pinniped-server-image",
						Command: []string{"pinniped-concierge-kube-cert-agent", "sleep"},
						Env: []corev1.EnvVar{
							{Name: "CERT_PATH", Value: "/path/to/signing.crt"},
							{Name: "KEY_PATH", Value: "/path/to/signing.key"},
						},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "test-volume",
							ReadOnly:  true,
							MountPath: "/path",
						}},
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("32Mi"),
								corev1.ResourceCPU:    resource.MustParse("20m"),
							},
							Requests: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("32Mi"),
								corev1.ResourceCPU:    resource.MustParse("0"),
							},
						},
						ImagePullPolicy: corev1.PullIfNotPresent,
					}},
					RestartPolicy:                 corev1.RestartPolicyAlways,
					TerminationGracePeriodSeconds: ptr.To[int64](0),
					ServiceAccountName:            "test-service-account-name",
					AutomountServiceAccountToken:  ptr.To(false),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:  ptr.To[int64](0),
						RunAsGroup: ptr.To[int64](0),
					},
					ImagePullSecrets: []corev1.LocalObjectReference{{
						Name: "pinniped-image-pull-secret",
					}},
					Volumes: []corev1.Volume{{
						Name: "test-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/host/path",
							},
						},
					}},
				},
			},
			MinReadySeconds: 10,
		},
	}

	// Older versions of Pinniped had a selector which included "app: app_name", e.g. "app: concierge".
	// Selector is an immutable field, but we want to support upgrading from those older versions anyway.
	oldStyleLabels := map[string]string{
		"app":                          "concierge",
		"extralabel":                   "labelvalue",
		"kube-cert-agent.pinniped.dev": "v2",
	}
	healthyAgentDeploymentWithOldStyleSelector := healthyAgentDeployment.DeepCopy()
	healthyAgentDeploymentWithOldStyleSelector.Spec.Selector = metav1.SetAsLabelSelector(oldStyleLabels)
	healthyAgentDeploymentWithOldStyleSelector.Spec.Template.ObjectMeta.Labels = oldStyleLabels
	healthyAgentDeploymentWithOldStyleSelector.UID = "fake-uid-abc123"                        // needs UID to test delete options
	healthyAgentDeploymentWithOldStyleSelector.ResourceVersion = "fake-resource-version-1234" // needs ResourceVersion to test delete options

	// The host network setting from the kube-controller-manager pod should be applied on the
	// deployment.
	healthyKubeControllerManagerPodWithHostNetwork := healthyKubeControllerManagerPod.DeepCopy()
	healthyKubeControllerManagerPodWithHostNetwork.Spec.HostNetwork = true

	//  We create an agent deployment that does not use host network and expect the
	// controller to add 'hostNetwork: true' to the spec.
	healthyAgentDeploymentWithHostNetwork := healthyAgentDeployment.DeepCopy()
	healthyAgentDeploymentWithHostNetwork.Spec.Template.Spec.HostNetwork = true

	// Make another kube-controller-manager pod that's similar, but has alternate CLI flags which we also support.
	healthyKubeControllerManagerPodWithAlternateArgs := healthyKubeControllerManagerPod.DeepCopy()
	healthyKubeControllerManagerPodWithAlternateArgs.Spec.Containers[0].Command = []string{
		"kube-controller-manager",
		"--some-flag",
		"--cluster-signing-kube-apiserver-client-cert-file", "/path/to/signing.crt",
		"--cluster-signing-kube-apiserver-client-key-file=/path/to/signing.key",
		"some arguments here",
		"--and-another-flag",
	}

	// Make another kube-controller-manager pod that's similar, but has both the standard and the alternate CLI flags,
	// which shouldn't really happen in practice because the Kubernetes docs say that you cannot use both style of flags,
	// but can be unit tested anyway.
	healthyKubeControllerManagerPodWithStandardAndAlternateArgs := healthyKubeControllerManagerPod.DeepCopy()
	healthyKubeControllerManagerPodWithStandardAndAlternateArgs.Spec.Containers[0].Command = []string{
		"kube-controller-manager",
		"--some-flag",
		"--cluster-signing-kube-apiserver-client-cert-file", "/path/to/should-be-ignored.crt",
		"--cluster-signing-kube-apiserver-client-key-file=/path/to/should-be-ignored.key",
		"--cluster-signing-cert-file", "/path/to/signing.crt",
		"--cluster-signing-key-file=/path/to/signing.key",
		"some arguments here",
		"--and-another-flag",
	}

	// Make another kube-controller-manager pod that's similar, but does not have the CLI flags we're expecting.
	// We should handle this by falling back to default values for the cert and key paths.
	healthyKubeControllerManagerPodWithoutArgs := healthyKubeControllerManagerPod.DeepCopy()
	healthyKubeControllerManagerPodWithoutArgs.Spec.Containers[0].Command = []string{"kube-controller-manager"}
	healthyAgentDeploymentWithDefaultedPaths := healthyAgentDeployment.DeepCopy()
	healthyAgentDeploymentWithDefaultedPaths.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
		{Name: "CERT_PATH", Value: "/etc/kubernetes/ca/ca.pem"},
		{Name: "KEY_PATH", Value: "/etc/kubernetes/ca/ca.key"},
	}

	// If an admission controller sets extra labels or annotations, that's okay.
	// We test this by ensuring that if a Deployment exists with extra labels, we don't try to delete them.
	healthyAgentDeploymentWithExtraLabels := healthyAgentDeployment.DeepCopy()
	healthyAgentDeploymentWithExtraLabels.Labels["some-additional-label"] = "some-additional-value"
	healthyAgentDeploymentWithExtraLabels.Annotations = map[string]string{"some-additional-annotation": "some-additional-value"}

	// If a Deployment with the wrong image exists, we want to change that.
	agentDeploymentWithExtraLabelsAndWrongImage := healthyAgentDeploymentWithExtraLabels.DeepCopy()
	agentDeploymentWithExtraLabelsAndWrongImage.Spec.Template.Spec.Containers[0].Image = "wrong-image"

	healthyAgentPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "concierge",
			Name:              "pinniped-concierge-kube-cert-agent-xyz-1234",
			UID:               types.UID("pinniped-concierge-kube-cert-agent-xyz-1234-test-uid"),
			Labels:            map[string]string{"kube-cert-agent.pinniped.dev": "v3"},
			CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
		},
		Spec:   corev1.PodSpec{},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	pendingAgentPod := healthyAgentPod.DeepCopy()
	pendingAgentPod.Status.Phase = corev1.PodPending

	validClusterInfoConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-public", Name: "cluster-info"},
		Data: map[string]string{"kubeconfig": here.Docf(`
			kind: Config
			apiVersion: v1
			clusters:
			- name: ""
			  cluster:
				certificate-authority-data: dGVzdC1rdWJlcm5ldGVzLWNh # "test-kubernetes-ca"
				server: https://test-kubernetes-endpoint.example.com
			`),
		},
	}

	mockExecSucceeds := func(t *testing.T, executor *mocks.MockPodCommandExecutorMockRecorder, dynamicCert *mocks.MockDynamicCertPrivateMockRecorder, execCache *cache.Expiring) {
		executor.Exec(gomock.Any(), "concierge", "pinniped-concierge-kube-cert-agent-xyz-1234", "sleeper", "pinniped-concierge-kube-cert-agent", "print").
			Return(`{"tls.crt": "dGVzdC1jZXJ0", "tls.key": "dGVzdC1rZXk="}`, nil) // "test-cert" / "test-key"
		dynamicCert.SetCertKeyContent([]byte("test-cert"), []byte("test-key")).
			Return(nil)
	}

	tests := []struct {
		name                             string
		discoveryURLOverride             *string
		pinnipedObjects                  []runtime.Object
		kubeObjects                      []runtime.Object
		addKubeReactions                 func(*kubefake.Clientset)
		mocks                            func(*testing.T, *mocks.MockPodCommandExecutorMockRecorder, *mocks.MockDynamicCertPrivateMockRecorder, *cache.Expiring)
		wantDistinctErrors               []string
		alsoAllowUndesiredDistinctErrors []string
		wantDistinctLogs                 []string
		wantAgentDeployment              *appsv1.Deployment
		wantDeploymentActionVerbs        []string
		wantDeploymentDeleteActionOpts   []metav1.DeleteOptions
		wantStrategy                     *conciergeconfigv1alpha1.CredentialIssuerStrategy
	}{
		{
			name: "no CredentialIssuer found",
			wantDistinctErrors: []string{
				`could not get CredentialIssuer to update: credentialissuer.config.concierge.pinniped.dev "pinniped-concierge-config" not found`,
			},
		},
		{
			name: "no kube-controller-manager pods",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "kube-system",
						Name:      "kube-proxy",
					},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
			wantDistinctErrors: []string{
				"could not find a healthy kube-controller-manager pod (0 candidates): " +
					"note that this error is the expected behavior for some cluster types, including most cloud provider clusters (e.g. GKE, AKS, EKS)",
			},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:   conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status: conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason: conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message: "could not find a healthy kube-controller-manager pod (0 candidates): " +
					"note that this error is the expected behavior for some cluster types, including most cloud provider clusters (e.g. GKE, AKS, EKS)",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "only unhealthy kube-controller-manager pods",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "kube-system",
						Name:      "kube-proxy",
					},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "kube-system",
						Name:      "kube-controller-manager-1",
						Labels:    map[string]string{"component": "kube-controller-manager"},
					},
					Spec:   corev1.PodSpec{},
					Status: corev1.PodStatus{Phase: corev1.PodPending},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "kube-system",
						Name:      "kube-controller-manager-2",
						Labels:    map[string]string{"component": "kube-controller-manager"},
					},
					Spec:   corev1.PodSpec{},
					Status: corev1.PodStatus{Phase: corev1.PodUnknown},
				},
			},
			wantDistinctErrors: []string{
				"could not find a healthy kube-controller-manager pod (2 candidates)",
			},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not find a healthy kube-controller-manager pod (2 candidates)",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "failed to created new deployment",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
			},
			addKubeReactions: func(clientset *kubefake.Clientset) {
				clientset.PrependReactor("create", "deployments", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("some creation error")
				})
			},
			wantDistinctErrors: []string{
				"could not ensure agent deployment: some creation error",
			},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"creating new deployment","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
			},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not ensure agent deployment: some creation error",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "created new deployment, no agent pods running yet",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:         "kube-system",
						Name:              "kube-controller-manager-3",
						Labels:            map[string]string{"component": "kube-controller-manager"},
						CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					},
					Spec:   corev1.PodSpec{},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
				healthyKubeControllerManagerPod,
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:         "kube-system",
						Name:              "kube-controller-manager-2",
						Labels:            map[string]string{"component": "kube-controller-manager"},
						CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					},
					Spec:   corev1.PodSpec{},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
				pendingAgentPod,
			},
			wantDistinctErrors: []string{
				"could not find a healthy agent pod (1 candidate)",
			},
			alsoAllowUndesiredDistinctErrors: []string{
				// due to the high amount of nondeterminism in this test, this error will sometimes also happen, but is not required to happen
				`could not ensure agent deployment: deployments.apps "pinniped-concierge-kube-cert-agent" already exists`,
			},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"creating new deployment","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
			},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch", "create"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not find a healthy agent pod (1 candidate)",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "created new deployment based on alternate supported controller-manager CLI flags, no agent pods running yet",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:         "kube-system",
						Name:              "kube-controller-manager-3",
						Labels:            map[string]string{"component": "kube-controller-manager"},
						CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					},
					Spec:   corev1.PodSpec{},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
				healthyKubeControllerManagerPodWithAlternateArgs,
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:         "kube-system",
						Name:              "kube-controller-manager-2",
						Labels:            map[string]string{"component": "kube-controller-manager"},
						CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					},
					Spec:   corev1.PodSpec{},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
				pendingAgentPod,
			},
			wantDistinctErrors: []string{
				"could not find a healthy agent pod (1 candidate)",
			},
			alsoAllowUndesiredDistinctErrors: []string{
				// due to the high amount of nondeterminism in this test, this error will sometimes also happen, but is not required to happen
				`could not ensure agent deployment: deployments.apps "pinniped-concierge-kube-cert-agent" already exists`,
			},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"creating new deployment","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
			},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch", "create"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not find a healthy agent pod (1 candidate)",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "created new deployment based on controller-manager which has both standard and alternate CLI flags (prefers the standard flags), no agent pods running yet",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:         "kube-system",
						Name:              "kube-controller-manager-3",
						Labels:            map[string]string{"component": "kube-controller-manager"},
						CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					},
					Spec:   corev1.PodSpec{},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
				healthyKubeControllerManagerPodWithStandardAndAlternateArgs,
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:         "kube-system",
						Name:              "kube-controller-manager-2",
						Labels:            map[string]string{"component": "kube-controller-manager"},
						CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					},
					Spec:   corev1.PodSpec{},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
				pendingAgentPod,
			},
			wantDistinctErrors: []string{
				"could not find a healthy agent pod (1 candidate)",
			},
			alsoAllowUndesiredDistinctErrors: []string{
				// due to the high amount of nondeterminism in this test, this error will sometimes also happen, but is not required to happen
				`could not ensure agent deployment: deployments.apps "pinniped-concierge-kube-cert-agent" already exists`,
			},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"creating new deployment","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
			},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch", "create"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not find a healthy agent pod (1 candidate)",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "created new deployment with defaulted paths, no agent pods running yet",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:         "kube-system",
						Name:              "kube-controller-manager-3",
						Labels:            map[string]string{"component": "kube-controller-manager"},
						CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					},
					Spec:   corev1.PodSpec{},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
				healthyKubeControllerManagerPodWithoutArgs,
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:         "kube-system",
						Name:              "kube-controller-manager-2",
						Labels:            map[string]string{"component": "kube-controller-manager"},
						CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					},
					Spec:   corev1.PodSpec{},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
				pendingAgentPod,
			},
			wantDistinctErrors: []string{
				"could not find a healthy agent pod (1 candidate)",
			},
			alsoAllowUndesiredDistinctErrors: []string{
				// due to the high amount of nondeterminism in this test, this error will sometimes also happen, but is not required to happen
				`could not ensure agent deployment: deployments.apps "pinniped-concierge-kube-cert-agent" already exists`,
			},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"creating new deployment","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
			},
			wantAgentDeployment:       healthyAgentDeploymentWithDefaultedPaths,
			wantDeploymentActionVerbs: []string{"list", "watch", "create"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not find a healthy agent pod (1 candidate)",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "to support upgrade from old versions, update to immutable selector field of existing deployment causes delete and recreate, no running agent pods yet",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeploymentWithOldStyleSelector,
				pendingAgentPod,
			},
			wantDistinctErrors: []string{
				"could not find a healthy agent pod (1 candidate)",
			},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"deleting deployment to update immutable Selector field","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"creating new deployment to update immutable Selector field","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
			},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch", "delete", "create"}, // must recreate deployment when Selector field changes
			wantDeploymentDeleteActionOpts: []metav1.DeleteOptions{
				testutil.NewPreconditions(healthyAgentDeploymentWithOldStyleSelector.UID, healthyAgentDeploymentWithOldStyleSelector.ResourceVersion),
			},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not find a healthy agent pod (1 candidate)",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "to support upgrade from old versions, update to immutable selector field of existing deployment causes delete and recreate, when delete fails",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeploymentWithOldStyleSelector,
				pendingAgentPod,
			},
			addKubeReactions: func(clientset *kubefake.Clientset) {
				clientset.PrependReactor("delete", "deployments", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("some delete error")
				})
			},
			wantDistinctErrors: []string{
				"could not ensure agent deployment: some delete error",
			},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"deleting deployment to update immutable Selector field","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
			},
			wantAgentDeployment: healthyAgentDeploymentWithOldStyleSelector, // couldn't be deleted, so it didn't change
			// delete to try to recreate deployment when Selector field changes, but delete always fails, so keeps trying to delete
			wantDeploymentActionVerbs: []string{"list", "watch", "delete", "delete"},
			wantDeploymentDeleteActionOpts: []metav1.DeleteOptions{
				testutil.NewPreconditions(healthyAgentDeploymentWithOldStyleSelector.UID, healthyAgentDeploymentWithOldStyleSelector.ResourceVersion),
				testutil.NewPreconditions(healthyAgentDeploymentWithOldStyleSelector.UID, healthyAgentDeploymentWithOldStyleSelector.ResourceVersion),
			},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not ensure agent deployment: some delete error",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "to support upgrade from old versions, update to immutable selector field of existing deployment causes delete and recreate, when delete succeeds but create fails",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeploymentWithOldStyleSelector,
				pendingAgentPod,
			},
			addKubeReactions: func(clientset *kubefake.Clientset) {
				clientset.PrependReactor("create", "deployments", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("some create error")
				})
			},
			wantDistinctErrors: []string{
				"could not ensure agent deployment: some create error",
			},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"deleting deployment to update immutable Selector field","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"creating new deployment to update immutable Selector field","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"creating new deployment","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
			},
			wantAgentDeployment: nil, // was deleted, but couldn't be recreated
			// delete to try to recreate deployment when Selector field changes, but create always fails, so keeps trying to recreate
			wantDeploymentActionVerbs: []string{"list", "watch", "delete", "create", "create"},
			wantDeploymentDeleteActionOpts: []metav1.DeleteOptions{
				testutil.NewPreconditions(healthyAgentDeploymentWithOldStyleSelector.UID, healthyAgentDeploymentWithOldStyleSelector.ResourceVersion),
			},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not ensure agent deployment: some create error",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "update to existing deployment, no running agent pods yet",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:         "kube-system",
						Name:              "kube-controller-manager-3",
						Labels:            map[string]string{"component": "kube-controller-manager"},
						CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
					},
					Spec:   corev1.PodSpec{},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:         "kube-system",
						Name:              "kube-controller-manager-2",
						Labels:            map[string]string{"component": "kube-controller-manager"},
						CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
					},
					Spec:   corev1.PodSpec{},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
				agentDeploymentWithExtraLabelsAndWrongImage,
				pendingAgentPod,
			},
			wantDistinctErrors: []string{
				"could not find a healthy agent pod (1 candidate)",
			},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"updating existing deployment","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
			},
			wantAgentDeployment:       healthyAgentDeploymentWithExtraLabels,
			wantDeploymentActionVerbs: []string{"list", "watch", "update"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not find a healthy agent pod (1 candidate)",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, but missing host network from kube-controller-manager",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPodWithHostNetwork,
				healthyAgentDeployment,
				healthyAgentPod,
			},
			wantDistinctErrors: []string{
				"failed to get kube-public/cluster-info configmap: configmap \"cluster-info\" not found",
			},
			wantAgentDeployment:       healthyAgentDeploymentWithHostNetwork,
			wantDeploymentActionVerbs: []string{"list", "watch", "update"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotGetClusterInfoStrategyReason,
				Message:        "failed to get kube-public/cluster-info configmap: configmap \"cluster-info\" not found",
				LastUpdateTime: metav1.NewTime(now),
			},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"updating existing deployment","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
			},
		},
		{
			name: "deployment exists, configmap missing",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
			},
			wantDistinctErrors: []string{
				"failed to get kube-public/cluster-info configmap: configmap \"cluster-info\" not found",
			},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotGetClusterInfoStrategyReason,
				Message:        "failed to get kube-public/cluster-info configmap: configmap \"cluster-info\" not found",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap missing key",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "kube-public", Name: "cluster-info"},
					Data:       map[string]string{},
				},
			},
			wantDistinctErrors: []string{
				"could not extract Kubernetes API endpoint info from kube-public/cluster-info configmap: missing \"kubeconfig\" key",
			},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotGetClusterInfoStrategyReason,
				Message:        "could not extract Kubernetes API endpoint info from kube-public/cluster-info configmap: missing \"kubeconfig\" key",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap key has invalid data",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "kube-public", Name: "cluster-info"},
					Data:       map[string]string{"kubeconfig": "'"},
				},
			},
			wantDistinctErrors: []string{
				"could not extract Kubernetes API endpoint info from kube-public/cluster-info configmap: key \"kubeconfig\" does not contain a valid kubeconfig",
			},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotGetClusterInfoStrategyReason,
				Message:        "could not extract Kubernetes API endpoint info from kube-public/cluster-info configmap: key \"kubeconfig\" does not contain a valid kubeconfig",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap kubeconfig has no clusters",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "kube-public", Name: "cluster-info"},
					Data:       map[string]string{"kubeconfig": "{}"},
				},
			},
			wantDistinctErrors: []string{
				"could not extract Kubernetes API endpoint info from kube-public/cluster-info configmap: kubeconfig in key \"kubeconfig\" does not contain any clusters",
			},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotGetClusterInfoStrategyReason,
				Message:        "could not extract Kubernetes API endpoint info from kube-public/cluster-info configmap: kubeconfig in key \"kubeconfig\" does not contain any clusters",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap is valid, exec into agent pod fails",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				validClusterInfoConfigMap,
			},
			mocks: func(t *testing.T, executor *mocks.MockPodCommandExecutorMockRecorder, dynamicCert *mocks.MockDynamicCertPrivateMockRecorder, execCache *cache.Expiring) {
				executor.Exec(gomock.Any(), "concierge", "pinniped-concierge-kube-cert-agent-xyz-1234", "sleeper", "pinniped-concierge-kube-cert-agent", "print").
					Return("", fmt.Errorf("some exec error")).
					AnyTimes()
			},
			wantDistinctErrors: []string{
				"could not exec into agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: some exec error",
			},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not exec into agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: some exec error",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap is valid, exec into agent pod returns invalid JSON",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				validClusterInfoConfigMap,
			},
			mocks: func(t *testing.T, executor *mocks.MockPodCommandExecutorMockRecorder, dynamicCert *mocks.MockDynamicCertPrivateMockRecorder, execCache *cache.Expiring) {
				executor.Exec(gomock.Any(), "concierge", "pinniped-concierge-kube-cert-agent-xyz-1234", "sleeper", "pinniped-concierge-kube-cert-agent", "print").
					Return("bogus-data", nil).
					AnyTimes()
			},
			wantDistinctErrors: []string{
				`failed to decode signing cert/key JSON from agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: invalid character 'b' looking for beginning of value`,
			},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        `failed to decode signing cert/key JSON from agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: invalid character 'b' looking for beginning of value`,
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap is valid, exec into agent pod returns invalid cert base64",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				validClusterInfoConfigMap,
			},
			mocks: func(t *testing.T, executor *mocks.MockPodCommandExecutorMockRecorder, dynamicCert *mocks.MockDynamicCertPrivateMockRecorder, execCache *cache.Expiring) {
				executor.Exec(gomock.Any(), "concierge", "pinniped-concierge-kube-cert-agent-xyz-1234", "sleeper", "pinniped-concierge-kube-cert-agent", "print").
					Return(`{"tls.crt": "invalid"}`, nil).
					AnyTimes()
			},
			wantDistinctErrors: []string{
				`failed to decode signing cert base64 from agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: illegal base64 data at input byte 4`,
			},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        `failed to decode signing cert base64 from agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: illegal base64 data at input byte 4`,
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap is valid, exec into agent pod returns invalid key base64",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				validClusterInfoConfigMap,
			},
			mocks: func(t *testing.T, executor *mocks.MockPodCommandExecutorMockRecorder, dynamicCert *mocks.MockDynamicCertPrivateMockRecorder, execCache *cache.Expiring) {
				executor.Exec(gomock.Any(), "concierge", "pinniped-concierge-kube-cert-agent-xyz-1234", "sleeper", "pinniped-concierge-kube-cert-agent", "print").
					Return(`{"tls.crt": "dGVzdAo=", "tls.key": "invalid"}`, nil).
					AnyTimes()
			},
			wantDistinctErrors: []string{
				`failed to decode signing key base64 from agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: illegal base64 data at input byte 4`,
			},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        `failed to decode signing key base64 from agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: illegal base64 data at input byte 4`,
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap is valid, exec into agent pod returns bogus certs",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				validClusterInfoConfigMap,
			},
			mocks: func(t *testing.T, executor *mocks.MockPodCommandExecutorMockRecorder, dynamicCert *mocks.MockDynamicCertPrivateMockRecorder, execCache *cache.Expiring) {
				executor.Exec(gomock.Any(), "concierge", "pinniped-concierge-kube-cert-agent-xyz-1234", "sleeper", "pinniped-concierge-kube-cert-agent", "print").
					Return(`{"tls.crt": "dGVzdC1jZXJ0", "tls.key": "dGVzdC1rZXk="}`, nil). // "test-cert" / "test-key"
					AnyTimes()
				dynamicCert.SetCertKeyContent([]byte("test-cert"), []byte("test-key")).
					Return(fmt.Errorf("some dynamic cert error")).
					AnyTimes()
			},
			wantDistinctErrors: []string{
				"failed to set signing cert/key content from agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: some dynamic cert error",
			},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "failed to set signing cert/key content from agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: some dynamic cert error",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap is valid, exec is cached",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				validClusterInfoConfigMap,
			},
			mocks: func(t *testing.T, executor *mocks.MockPodCommandExecutorMockRecorder, dynamicCert *mocks.MockDynamicCertPrivateMockRecorder, execCache *cache.Expiring) {
				// If we pre-fill the cache here, we should never see any calls to the executor or dynamicCert mocks.
				execCache.Set(healthyAgentPod.UID, struct{}{}, 1*time.Hour)
			},
			wantDistinctErrors:        []string{""},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch"},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
				Reason:         conciergeconfigv1alpha1.FetchedKeyStrategyReason,
				Message:        "key was fetched successfully",
				LastUpdateTime: metav1.NewTime(now),
				Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
					Type: conciergeconfigv1alpha1.TokenCredentialRequestAPIFrontendType,
					TokenCredentialRequestAPIInfo: &conciergeconfigv1alpha1.TokenCredentialRequestAPIInfo{
						Server:                   "https://test-kubernetes-endpoint.example.com",
						CertificateAuthorityData: "dGVzdC1rdWJlcm5ldGVzLWNh",
					},
				},
			},
		},
		{
			name: "deployment exists has old selector, but agent pod exists with correct labels, configmap is valid, exec succeeds",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeploymentWithOldStyleSelector,
				healthyAgentPod,
				validClusterInfoConfigMap,
			},
			addKubeReactions: func(clientset *kubefake.Clientset) {
				clientset.PrependReactor("delete", "deployments", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("some delete error")
				})
			},
			mocks: mockExecSucceeds, // expect an attempt to fill the cache
			wantDistinctErrors: []string{
				"could not ensure agent deployment: some delete error",
			},
			wantAgentDeployment: healthyAgentDeploymentWithOldStyleSelector, // couldn't be deleted, so it didn't change
			// delete to try to recreate deployment when Selector field changes, but delete always fails, so keeps trying to delete
			wantDeploymentActionVerbs: []string{"list", "watch", "delete", "delete"},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).createOrUpdateDeployment","message":"deleting deployment to update immutable Selector field","deployment":{"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"},"templatePod":{"name":"kube-controller-manager-1","namespace":"kube-system"}}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).loadSigningKey","message":"successfully loaded signing key from agent pod into cache"}`,
			},
			wantDeploymentDeleteActionOpts: []metav1.DeleteOptions{
				testutil.NewPreconditions(healthyAgentDeploymentWithOldStyleSelector.UID, healthyAgentDeploymentWithOldStyleSelector.ResourceVersion),
				testutil.NewPreconditions(healthyAgentDeploymentWithOldStyleSelector.UID, healthyAgentDeploymentWithOldStyleSelector.ResourceVersion),
			},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not ensure agent deployment: some delete error",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap is valid, exec succeeds",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				validClusterInfoConfigMap,
			},
			mocks:                     mockExecSucceeds,
			wantDistinctErrors:        []string{""},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch"},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).loadSigningKey","message":"successfully loaded signing key from agent pod into cache"}`,
			},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
				Reason:         conciergeconfigv1alpha1.FetchedKeyStrategyReason,
				Message:        "key was fetched successfully",
				LastUpdateTime: metav1.NewTime(now),
				Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
					Type: conciergeconfigv1alpha1.TokenCredentialRequestAPIFrontendType,
					TokenCredentialRequestAPIInfo: &conciergeconfigv1alpha1.TokenCredentialRequestAPIInfo{
						Server:                   "https://test-kubernetes-endpoint.example.com",
						CertificateAuthorityData: "dGVzdC1rdWJlcm5ldGVzLWNh",
					},
				},
			},
		},
		{
			name: "deployment exists, configmap is valid, exec succeeds, overridden discovery URL",
			pinnipedObjects: []runtime.Object{
				initialCredentialIssuer,
			},
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				validClusterInfoConfigMap,
			},
			discoveryURLOverride:      ptr.To("https://overridden-server.example.com/some/path"),
			mocks:                     mockExecSucceeds,
			wantDistinctErrors:        []string{""},
			wantAgentDeployment:       healthyAgentDeployment,
			wantDeploymentActionVerbs: []string{"list", "watch"},
			wantDistinctLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"kube-cert-agent-controller","caller":"kubecertagent/kubecertagent.go:<line>$kubecertagent.(*agentController).loadSigningKey","message":"successfully loaded signing key from agent pod into cache"}`,
			},
			wantStrategy: &conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
				Reason:         conciergeconfigv1alpha1.FetchedKeyStrategyReason,
				Message:        "key was fetched successfully",
				LastUpdateTime: metav1.NewTime(now),
				Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
					Type: conciergeconfigv1alpha1.TokenCredentialRequestAPIFrontendType,
					TokenCredentialRequestAPIInfo: &conciergeconfigv1alpha1.TokenCredentialRequestAPIInfo{
						Server:                   "https://overridden-server.example.com/some/path",
						CertificateAuthorityData: "dGVzdC1rdWJlcm5ldGVzLWNh",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conciergeClientset := conciergefake.NewSimpleClientset(tt.pinnipedObjects...)
			conciergeInformers := conciergeinformers.NewSharedInformerFactory(conciergeClientset, 0)

			kubeClientset := kubefake.NewSimpleClientset(tt.kubeObjects...)
			if tt.addKubeReactions != nil {
				tt.addKubeReactions(kubeClientset)
			}

			kubeInformers := informers.NewSharedInformerFactory(kubeClientset, 0)

			logger, log := plog.TestLogger(t)

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockExecutor := mocks.NewMockPodCommandExecutor(ctrl)
			mockDynamicCert := mocks.NewMockDynamicCertPrivate(ctrl)
			fakeClock := clocktesting.NewFakeClock(now)
			execCache := cache.NewExpiringWithClock(fakeClock)
			if tt.mocks != nil {
				tt.mocks(t, mockExecutor.EXPECT(), mockDynamicCert.EXPECT(), execCache)
			}
			controller := newAgentController(
				AgentConfig{
					Namespace:                 "concierge",
					ContainerImage:            "pinniped-server-image",
					ServiceAccountName:        "test-service-account-name",
					NamePrefix:                "pinniped-concierge-kube-cert-agent-",
					ContainerImagePullSecrets: []string{"pinniped-image-pull-secret"},
					CredentialIssuerName:      initialCredentialIssuer.Name,
					Labels: map[string]string{
						"extralabel": "labelvalue",
						// The special label "app" should never be added to the Pods of the kube cert agent Deployment.
						// Older versions of Pinniped added this label, but it matches the Selector of the main
						// Concierge Deployment, so we do not want it to exist on the Kube cert agent pods.
						"app": "anything",
					},
					DiscoveryURLOverride: tt.discoveryURLOverride,
				},
				&kubeclient.Client{Kubernetes: kubeClientset, PinnipedConcierge: conciergeClientset},
				kubeInformers.Core().V1().Pods(),
				kubeInformers.Apps().V1().Deployments(),
				kubeInformers.Core().V1().Pods(),
				kubeInformers.Core().V1().ConfigMaps(),
				conciergeInformers.Config().V1alpha1().CredentialIssuers(),
				mockExecutor,
				mockDynamicCert,
				fakeClock,
				execCache,
				logger,
			)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			errorMessages := runControllerUntilQuiet(ctx, t, controller, hasDeploymentSynced(kubeClientset, kubeInformers), kubeInformers, conciergeInformers)

			actualErrors := deduplicate(errorMessages)
			assert.Subsetf(t, actualErrors, tt.wantDistinctErrors, "required error(s) were not found in the actual errors")

			allAllowedErrors := slices.Concat(tt.wantDistinctErrors, tt.alsoAllowUndesiredDistinctErrors)
			assert.Subsetf(t, allAllowedErrors, actualErrors, "actual errors contained additional error(s) which is not expected by the test")

			assert.Equal(t, tt.wantDistinctLogs, deduplicate(testutil.SplitByNewline(log.String())), "unexpected logs")

			// Assert on all actions that happened to deployments.
			var actualDeploymentActionVerbs []string
			var actualDeleteActionOpts []metav1.DeleteOptions
			for _, a := range kubeClientset.Actions() {
				if a.GetResource().Resource == "deployments" && a.GetVerb() != "get" { // ignore gets caused by hasDeploymentSynced
					actualDeploymentActionVerbs = append(actualDeploymentActionVerbs, a.GetVerb())
					if deleteAction, ok := a.(coretesting.DeleteAction); ok {
						actualDeleteActionOpts = append(actualDeleteActionOpts, deleteAction.GetDeleteOptions())
					}
				}
			}
			if tt.wantDeploymentActionVerbs != nil {
				assert.Equal(t, tt.wantDeploymentActionVerbs, actualDeploymentActionVerbs)
			}
			if tt.wantDeploymentDeleteActionOpts != nil {
				assert.Equal(t, tt.wantDeploymentDeleteActionOpts, actualDeleteActionOpts)
			}

			// Assert that the agent deployment is in the expected final state.
			deployments, err := kubeClientset.AppsV1().Deployments("concierge").List(ctx, metav1.ListOptions{})
			require.NoError(t, err)
			if tt.wantAgentDeployment == nil {
				assert.Empty(t, deployments.Items, "did not expect an agent deployment")
			} else { //nolint:gocritic
				if assert.Len(t, deployments.Items, 1, "expected a single agent deployment") {
					assert.Equal(t, tt.wantAgentDeployment, &deployments.Items[0])
				}
			}

			// Assert that the CredentialIssuer is in the expected final state
			if tt.wantStrategy != nil {
				credIssuer, err := conciergeClientset.ConfigV1alpha1().CredentialIssuers().Get(ctx, initialCredentialIssuer.Name, metav1.GetOptions{})
				ok := assert.NoError(t, err)
				if ok && assert.Len(t, credIssuer.Status.Strategies, 1, "expected a single strategy in the CredentialIssuer") {
					assert.Equal(t, tt.wantStrategy, &credIssuer.Status.Strategies[0])
				}
			}
		})
	}
}

func TestMergeLabelsAndAnnotations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		existing metav1.ObjectMeta
		desired  metav1.ObjectMeta
		expected metav1.ObjectMeta
	}{
		{
			name:     "empty",
			existing: metav1.ObjectMeta{},
			desired:  metav1.ObjectMeta{},
			expected: metav1.ObjectMeta{},
		},
		{
			name:     "new labels and annotations",
			existing: metav1.ObjectMeta{},
			desired: metav1.ObjectMeta{
				Labels:      map[string]string{"k1": "v1"},
				Annotations: map[string]string{"k2": "v2"},
			},
			expected: metav1.ObjectMeta{
				Labels:      map[string]string{"k1": "v1"},
				Annotations: map[string]string{"k2": "v2"},
			},
		},
		{
			name: "merged labels and annotations",
			existing: metav1.ObjectMeta{
				Namespace:   "test-namespace",
				Name:        "test-name",
				Labels:      map[string]string{"k1": "old-v1", "extra-1": "v3"},
				Annotations: map[string]string{"k2": "old-v2", "extra-2": "v4"},
			},
			desired: metav1.ObjectMeta{
				Labels:      map[string]string{"k1": "v1"},
				Annotations: map[string]string{"k2": "v2"},
			},
			expected: metav1.ObjectMeta{
				Namespace:   "test-namespace",
				Name:        "test-name",
				Labels:      map[string]string{"k1": "v1", "extra-1": "v3"},
				Annotations: map[string]string{"k2": "v2", "extra-2": "v4"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			existingCopy := tt.existing.DeepCopy()
			desiredCopy := tt.desired.DeepCopy()
			got := mergeLabelsAndAnnotations(tt.existing, tt.desired)
			require.Equal(t, tt.expected, got)
			require.Equal(t, existingCopy, tt.existing.DeepCopy(), "input was modified!")
			require.Equal(t, desiredCopy, tt.desired.DeepCopy(), "input was modified!")
		})
	}
}

func deduplicate(strings []string) []string {
	if strings == nil {
		return nil
	}
	seen, result := map[string]bool{}, make([]string, 0, len(strings))
	for _, s := range strings {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func runControllerUntilQuiet(ctx context.Context, t *testing.T, controller controllerlib.Controller, synced func(ctx context.Context, t *testing.T), informers ...controllerinit.Informer) []string {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var syncErrs []error                 // track the errors we see during each iteration
	errorStream := make(chan error, 100) // do not block the controller loop
	controllerlib.TestWrap(t, controller, func(syncer controllerlib.Syncer) controllerlib.Syncer {
		return controllerlib.SyncFunc(func(ctx controllerlib.Context) error {
			synced(ctx.Context, t) // make sure that our informer has caught up with our client

			// if we got the same error twice in a row, prevent the controller sync loop from running
			if len(syncErrs) >= 2 {
				lastErr := syncErrs[len(syncErrs)-1]
				secondToLastErr := syncErrs[len(syncErrs)-2]
				if lastErr != nil && secondToLastErr != nil && lastErr.Error() == secondToLastErr.Error() {
					cancel() // not explicitly required but matches our intent
					return nil
				}
			}

			err := syncer.Sync(ctx)
			errorStream <- err

			syncErrs = append(syncErrs, err)

			return err
		})
	})

	// start and sync the informers before running the controller
	runController, err := controllerinit.Prepare(
		func(ctx context.Context) { controller.Run(ctx, 1) },
		func(ctx context.Context, runner controllerinit.Runner) { runner(ctx) },
		informers...,
	)(ctx)
	require.NoError(t, err)
	go runController(ctx)

	// Wait until the controller is quiet for two seconds.
	var errorMessages []string
done:
	for {
		select {
		case err := <-errorStream:
			if err == nil {
				errorMessages = append(errorMessages, "")
			} else {
				errorMessages = append(errorMessages, err.Error())
			}
		case <-time.After(2 * time.Second):
			break done
		}
	}
	return errorMessages
}

func hasDeploymentSynced(client kubernetes.Interface, kubeInformers informers.SharedInformerFactory) func(ctx context.Context, t *testing.T) {
	return func(ctx context.Context, t *testing.T) {
		testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
			realDep, realErr := client.AppsV1().Deployments("concierge").
				Get(ctx, "pinniped-concierge-kube-cert-agent", metav1.GetOptions{})

			cachedDep, cachedErr := kubeInformers.Apps().V1().Deployments().Lister().Deployments("concierge").
				Get("pinniped-concierge-kube-cert-agent")

			if apierrors.IsNotFound(realErr) && apierrors.IsNotFound(cachedErr) {
				return
			}

			requireEventually.NoError(realErr)
			requireEventually.NoError(cachedErr)

			requireEventually.Equal(realDep, cachedDep)
		}, 2*time.Second, 100*time.Millisecond)
	}
}
