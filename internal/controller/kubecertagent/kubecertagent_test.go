// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertagent

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/client-go/informers"
	kubefake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/utils/pointer"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	conciergefake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	"go.pinniped.dev/internal/controller/kubecertagent/mocks"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/testutil/testlogger"
)

func TestAgentController(t *testing.T) {
	t.Parallel()
	now := time.Date(2021, 4, 13, 9, 57, 0, 0, time.UTC)

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
			Labels:    map[string]string{"extralabel": "labelvalue"},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: pointer.Int32Ptr(1),
			Selector: metav1.SetAsLabelSelector(map[string]string{
				"extralabel":                   "labelvalue",
				"kube-cert-agent.pinniped.dev": "v2",
			}),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"extralabel":                   "labelvalue",
						"kube-cert-agent.pinniped.dev": "v2",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:    "sleeper",
						Image:   "pinniped-server-image",
						Command: []string{"/bin/sleep", "infinity"},
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
								corev1.ResourceMemory: resource.MustParse("16Mi"),
								corev1.ResourceCPU:    resource.MustParse("10m"),
							},
							Requests: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("16Mi"),
								corev1.ResourceCPU:    resource.MustParse("10m"),
							},
						},
						ImagePullPolicy: corev1.PullIfNotPresent,
					}},
					RestartPolicy:                 corev1.RestartPolicyAlways,
					TerminationGracePeriodSeconds: pointer.Int64Ptr(0),
					ServiceAccountName:            "test-service-account-name",
					AutomountServiceAccountToken:  pointer.BoolPtr(false),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:  pointer.Int64Ptr(0),
						RunAsGroup: pointer.Int64Ptr(0),
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
			Labels:            map[string]string{"kube-cert-agent.pinniped.dev": "v2"},
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
		executor.Exec("concierge", "pinniped-concierge-kube-cert-agent-xyz-1234", "sh", "-c", "cat ${CERT_PATH}; echo; echo; cat ${KEY_PATH}").
			Return("test-cert\n\n\ntest-key", nil)
		dynamicCert.SetCertKeyContent([]byte("test-cert"), []byte("test-key")).
			Return(nil)
	}

	tests := []struct {
		name                 string
		discoveryURLOverride *string
		kubeObjects          []runtime.Object
		addKubeReactions     func(*kubefake.Clientset)
		mocks                func(*testing.T, *mocks.MockPodCommandExecutorMockRecorder, *mocks.MockDynamicCertPrivateMockRecorder, *cache.Expiring)
		wantDistinctErrors   []string
		wantDistinctLogs     []string
		wantAgentDeployment  *appsv1.Deployment
		wantStrategy         *configv1alpha1.CredentialIssuerStrategy
	}{
		{
			name: "no kube-controller-manager pods",
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
				"could not find a healthy kube-controller-manager pod (0 candidates)",
			},
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.ErrorStrategyStatus,
				Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not find a healthy kube-controller-manager pod (0 candidates)",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "only unhealthy kube-controller-manager pods",
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
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.ErrorStrategyStatus,
				Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not find a healthy kube-controller-manager pod (2 candidates)",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "failed to created new deployment",
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
				`kube-cert-agent-controller "level"=0 "msg"="creating new deployment" "deployment"={"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"} "templatePod"={"name":"kube-controller-manager-1","namespace":"kube-system"}`,
			},
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.ErrorStrategyStatus,
				Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not ensure agent deployment: some creation error",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "created new deployment, no agent pods running yet",
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
			wantDistinctLogs: []string{
				`kube-cert-agent-controller "level"=0 "msg"="creating new deployment" "deployment"={"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"} "templatePod"={"name":"kube-controller-manager-1","namespace":"kube-system"}`,
			},
			wantAgentDeployment: healthyAgentDeployment,
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.ErrorStrategyStatus,
				Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not find a healthy agent pod (1 candidate)",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "created new deployment with defaulted paths, no agent pods running yet",
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
			wantDistinctLogs: []string{
				`kube-cert-agent-controller "level"=0 "msg"="creating new deployment" "deployment"={"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"} "templatePod"={"name":"kube-controller-manager-1","namespace":"kube-system"}`,
			},
			wantAgentDeployment: healthyAgentDeploymentWithDefaultedPaths,
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.ErrorStrategyStatus,
				Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not find a healthy agent pod (1 candidate)",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "update to existing deployment, no running agent pods yet",
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
				`kube-cert-agent-controller "level"=0 "msg"="updating existing deployment" "deployment"={"name":"pinniped-concierge-kube-cert-agent","namespace":"concierge"} "templatePod"={"name":"kube-controller-manager-1","namespace":"kube-system"}`,
			},
			wantAgentDeployment: healthyAgentDeploymentWithExtraLabels,
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.ErrorStrategyStatus,
				Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not find a healthy agent pod (1 candidate)",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap missing",
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
			},
			wantDistinctErrors: []string{
				"failed to get kube-public/cluster-info configmap: configmap \"cluster-info\" not found",
			},
			wantAgentDeployment: healthyAgentDeployment,
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.ErrorStrategyStatus,
				Reason:         configv1alpha1.CouldNotGetClusterInfoStrategyReason,
				Message:        "failed to get kube-public/cluster-info configmap: configmap \"cluster-info\" not found",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap missing key",
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
			wantAgentDeployment: healthyAgentDeployment,
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.ErrorStrategyStatus,
				Reason:         configv1alpha1.CouldNotGetClusterInfoStrategyReason,
				Message:        "could not extract Kubernetes API endpoint info from kube-public/cluster-info configmap: missing \"kubeconfig\" key",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap key has invalid data",
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
			wantAgentDeployment: healthyAgentDeployment,
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.ErrorStrategyStatus,
				Reason:         configv1alpha1.CouldNotGetClusterInfoStrategyReason,
				Message:        "could not extract Kubernetes API endpoint info from kube-public/cluster-info configmap: key \"kubeconfig\" does not contain a valid kubeconfig",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap kubeconfig has no clusters",
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
			wantAgentDeployment: healthyAgentDeployment,
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.ErrorStrategyStatus,
				Reason:         configv1alpha1.CouldNotGetClusterInfoStrategyReason,
				Message:        "could not extract Kubernetes API endpoint info from kube-public/cluster-info configmap: kubeconfig in key \"kubeconfig\" does not contain any clusters",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap is valid,, exec into agent pod fails",
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				validClusterInfoConfigMap,
			},
			mocks: func(t *testing.T, executor *mocks.MockPodCommandExecutorMockRecorder, dynamicCert *mocks.MockDynamicCertPrivateMockRecorder, execCache *cache.Expiring) {
				executor.Exec("concierge", "pinniped-concierge-kube-cert-agent-xyz-1234", "sh", "-c", "cat ${CERT_PATH}; echo; echo; cat ${KEY_PATH}").
					Return("", fmt.Errorf("some exec error")).
					AnyTimes()
			},
			wantDistinctErrors: []string{
				"could not exec into agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: some exec error",
			},
			wantAgentDeployment: healthyAgentDeployment,
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.ErrorStrategyStatus,
				Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "could not exec into agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: some exec error",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap is valid, exec into agent pod returns bogus certs",
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				validClusterInfoConfigMap,
			},
			mocks: func(t *testing.T, executor *mocks.MockPodCommandExecutorMockRecorder, dynamicCert *mocks.MockDynamicCertPrivateMockRecorder, execCache *cache.Expiring) {
				executor.Exec("concierge", "pinniped-concierge-kube-cert-agent-xyz-1234", "sh", "-c", "cat ${CERT_PATH}; echo; echo; cat ${KEY_PATH}").
					Return("bogus-data", nil).
					AnyTimes()
				dynamicCert.SetCertKeyContent([]byte(""), []byte("")).
					Return(fmt.Errorf("some dynamic cert error")).
					AnyTimes()
			},
			wantDistinctErrors: []string{
				"failed to set signing cert/key content from agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: some dynamic cert error",
			},
			wantAgentDeployment: healthyAgentDeployment,
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.ErrorStrategyStatus,
				Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
				Message:        "failed to set signing cert/key content from agent pod concierge/pinniped-concierge-kube-cert-agent-xyz-1234: some dynamic cert error",
				LastUpdateTime: metav1.NewTime(now),
			},
		},
		{
			name: "deployment exists, configmap is valid, exec is cached",
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
			wantDistinctErrors:  []string{""},
			wantAgentDeployment: healthyAgentDeployment,
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.SuccessStrategyStatus,
				Reason:         configv1alpha1.FetchedKeyStrategyReason,
				Message:        "key was fetched successfully",
				LastUpdateTime: metav1.NewTime(now),
				Frontend: &configv1alpha1.CredentialIssuerFrontend{
					Type: configv1alpha1.TokenCredentialRequestAPIFrontendType,
					TokenCredentialRequestAPIInfo: &configv1alpha1.TokenCredentialRequestAPIInfo{
						Server:                   "https://test-kubernetes-endpoint.example.com",
						CertificateAuthorityData: "dGVzdC1rdWJlcm5ldGVzLWNh",
					},
				},
			},
		},
		{
			name: "deployment exists, configmap is valid, exec succeeds",
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				validClusterInfoConfigMap,
			},
			mocks:               mockExecSucceeds,
			wantDistinctErrors:  []string{""},
			wantAgentDeployment: healthyAgentDeployment,
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.SuccessStrategyStatus,
				Reason:         configv1alpha1.FetchedKeyStrategyReason,
				Message:        "key was fetched successfully",
				LastUpdateTime: metav1.NewTime(now),
				Frontend: &configv1alpha1.CredentialIssuerFrontend{
					Type: configv1alpha1.TokenCredentialRequestAPIFrontendType,
					TokenCredentialRequestAPIInfo: &configv1alpha1.TokenCredentialRequestAPIInfo{
						Server:                   "https://test-kubernetes-endpoint.example.com",
						CertificateAuthorityData: "dGVzdC1rdWJlcm5ldGVzLWNh",
					},
				},
			},
		},
		{
			name: "deployment exists, configmap is valid, exec succeeds, overridden discovery URL",
			kubeObjects: []runtime.Object{
				healthyKubeControllerManagerPod,
				healthyAgentDeployment,
				healthyAgentPod,
				validClusterInfoConfigMap,
			},
			discoveryURLOverride: pointer.StringPtr("https://overridden-server.example.com/some/path"),
			mocks:                mockExecSucceeds,
			wantDistinctErrors:   []string{""},
			wantAgentDeployment:  healthyAgentDeployment,
			wantStrategy: &configv1alpha1.CredentialIssuerStrategy{
				Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         configv1alpha1.SuccessStrategyStatus,
				Reason:         configv1alpha1.FetchedKeyStrategyReason,
				Message:        "key was fetched successfully",
				LastUpdateTime: metav1.NewTime(now),
				Frontend: &configv1alpha1.CredentialIssuerFrontend{
					Type: configv1alpha1.TokenCredentialRequestAPIFrontendType,
					TokenCredentialRequestAPIInfo: &configv1alpha1.TokenCredentialRequestAPIInfo{
						Server:                   "https://overridden-server.example.com/some/path",
						CertificateAuthorityData: "dGVzdC1rdWJlcm5ldGVzLWNh",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kubeClientset := kubefake.NewSimpleClientset(tt.kubeObjects...)
			if tt.addKubeReactions != nil {
				tt.addKubeReactions(kubeClientset)
			}

			conciergeClientset := conciergefake.NewSimpleClientset()
			kubeInformers := informers.NewSharedInformerFactory(kubeClientset, 0)
			log := testlogger.New(t)

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockExecutor := mocks.NewMockPodCommandExecutor(ctrl)
			mockDynamicCert := mocks.NewMockDynamicCertPrivate(ctrl)
			fakeClock := clock.NewFakeClock(now)
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
					CredentialIssuerName:      "pinniped-concierge-config",
					Labels:                    map[string]string{"extralabel": "labelvalue"},
					DiscoveryURLOverride:      tt.discoveryURLOverride,
				},
				&kubeclient.Client{Kubernetes: kubeClientset, PinnipedConcierge: conciergeClientset},
				kubeInformers.Core().V1().Pods(),
				kubeInformers.Apps().V1().Deployments(),
				kubeInformers.Core().V1().Pods(),
				kubeInformers.Core().V1().ConfigMaps(),
				mockExecutor,
				mockDynamicCert,
				fakeClock,
				execCache,
				log,
				controllerlib.WithMaxRetries(1),
			)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			errorMessages := runControllerUntilQuiet(ctx, t, controller, kubeInformers)
			assert.Equal(t, tt.wantDistinctErrors, deduplicate(errorMessages), "unexpected errors")
			assert.Equal(t, tt.wantDistinctLogs, deduplicate(log.Lines()), "unexpected logs")

			// Assert that the agent deployment is in the expected final state.
			deployments, err := kubeClientset.AppsV1().Deployments("concierge").List(ctx, metav1.ListOptions{})
			require.NoError(t, err)
			if tt.wantAgentDeployment == nil {
				require.Empty(t, deployments.Items, "did not expect an agent deployment")
			} else {
				require.Len(t, deployments.Items, 1, "expected a single agent deployment")
				require.Equal(t, tt.wantAgentDeployment, &deployments.Items[0])
			}

			// Assert that the CredentialIssuer is in the expected final state
			credIssuer, err := conciergeClientset.ConfigV1alpha1().CredentialIssuers().Get(ctx, "pinniped-concierge-config", metav1.GetOptions{})
			require.NoError(t, err)
			require.Len(t, credIssuer.Status.Strategies, 1, "expected a single strategy in the CredentialIssuer")
			require.Equal(t, tt.wantStrategy, &credIssuer.Status.Strategies[0])
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			existingCopy := tt.existing.DeepCopy()
			desiredCopy := tt.desired.DeepCopy()
			got := mergeLabelsAndAnnotations(tt.existing, tt.desired)
			require.Equal(t, tt.expected, got)
			require.Equal(t, existingCopy, &tt.existing, "input was modified!")
			require.Equal(t, desiredCopy, &tt.desired, "input was modified!")
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

func runControllerUntilQuiet(ctx context.Context, t *testing.T, controller controllerlib.Controller, informers ...informers.SharedInformerFactory) []string {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errorStream := make(chan error)
	controllerlib.TestWrap(t, controller, func(syncer controllerlib.Syncer) controllerlib.Syncer {
		controller.Name()
		return controllerlib.SyncFunc(func(ctx controllerlib.Context) error {
			err := syncer.Sync(ctx)
			errorStream <- err
			return err
		})
	})

	for _, informer := range informers {
		informer.Start(ctx.Done())
	}

	go controller.Run(ctx, 1)

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
