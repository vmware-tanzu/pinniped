// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package kubecertagent provides controllers that ensure a set of pods (the kube-cert-agent), is
// colocated with the Kubernetes controller manager so that Pinniped can access its signing keys.
//
// Note: the controllers use a filter that accepts all pods that look like the controller manager or
// an agent pod, across any add/update/delete event. Each of the controllers only care about a
// subset of these events in reality, but the liberal filter implementation serves as an MVP.
package kubecertagent

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/clock"
	corev1informers "k8s.io/client-go/informers/core/v1"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	"go.pinniped.dev/internal/plog"
)

const (
	// ControllerManagerNamespace is the assumed namespace of the kube-controller-manager pod(s).
	ControllerManagerNamespace = "kube-system"

	// controllerManagerNameAnnotationKey is used to store an agent pod's parent's name, i.e., the
	// name of the controller manager pod with which it is supposed to be in sync.
	controllerManagerNameAnnotationKey = "kube-cert-agent.pinniped.dev/controller-manager-name"
	// controllerManagerUIDAnnotationKey is used to store an agent pod's parent's UID, i.e., the UID
	// of the controller manager pod with which it is supposed to be in sync.
	controllerManagerUIDAnnotationKey = "kube-cert-agent.pinniped.dev/controller-manager-uid"

	// agentPodLabelKey is used to identify which pods are created by the kube-cert-agent
	// controllers.
	agentPodLabelKey   = "kube-cert-agent.pinniped.dev"
	agentPodLabelValue = "true"

	// agentPodCertPathAnnotationKey is the annotation that the kube-cert-agent pod will use
	// to communicate the in-pod path to the kube API's certificate.
	agentPodCertPathAnnotationKey = "kube-cert-agent.pinniped.dev/cert-path"

	// agentPodKeyPathAnnotationKey is the annotation that the kube-cert-agent pod will use
	// to communicate the in-pod path to the kube API's key.
	agentPodKeyPathAnnotationKey = "kube-cert-agent.pinniped.dev/key-path"
)

type AgentPodConfig struct {
	// The namespace in which agent pods will be created.
	Namespace string

	// The container image used for the agent pods.
	ContainerImage string

	// The name prefix for each of the agent pods.
	PodNamePrefix string

	// ContainerImagePullSecrets is a list of names of Kubernetes Secret objects that will be used as
	// ImagePullSecrets on the kube-cert-agent pods.
	ContainerImagePullSecrets []string

	// Additional labels that should be added to every agent pod during creation.
	AdditionalLabels map[string]string
}

type CredentialIssuerLocationConfig struct {
	// The resource name for the CredentialIssuer to be created/updated.
	Name string
}

func (c *AgentPodConfig) Labels() map[string]string {
	allLabels := map[string]string{
		agentPodLabelKey: agentPodLabelValue,
	}
	for k, v := range c.AdditionalLabels {
		allLabels[k] = v
	}
	return allLabels
}

func (c *AgentPodConfig) AgentSelector() labels.Selector {
	return labels.SelectorFromSet(map[string]string{agentPodLabelKey: agentPodLabelValue})
}

func (c *AgentPodConfig) newAgentPod(controllerManagerPod *corev1.Pod) *corev1.Pod {
	terminateImmediately := int64(0)
	rootID := int64(0)
	f := false
	falsePtr := &f

	imagePullSecrets := []corev1.LocalObjectReference{}
	for _, imagePullSecret := range c.ContainerImagePullSecrets {
		imagePullSecrets = append(
			imagePullSecrets,
			corev1.LocalObjectReference{
				Name: imagePullSecret,
			},
		)
	}

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s%s", c.PodNamePrefix, hash(controllerManagerPod)),
			Namespace: c.Namespace,
			Labels:    c.Labels(),
			Annotations: map[string]string{
				controllerManagerNameAnnotationKey: controllerManagerPod.Name,
				controllerManagerUIDAnnotationKey:  string(controllerManagerPod.UID),
			},
		},
		Spec: corev1.PodSpec{
			TerminationGracePeriodSeconds: &terminateImmediately,
			ImagePullSecrets:              imagePullSecrets,
			Containers: []corev1.Container{
				{
					Name:            "sleeper",
					Image:           c.ContainerImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Command:         []string{"/bin/sleep", "infinity"},
					VolumeMounts:    controllerManagerPod.Spec.Containers[0].VolumeMounts,
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
				},
			},
			Volumes:                      controllerManagerPod.Spec.Volumes,
			RestartPolicy:                corev1.RestartPolicyNever,
			NodeSelector:                 controllerManagerPod.Spec.NodeSelector,
			AutomountServiceAccountToken: falsePtr,
			NodeName:                     controllerManagerPod.Spec.NodeName,
			Tolerations:                  controllerManagerPod.Spec.Tolerations,
			// We need to run the agent pod as root since the file permissions
			// on the cluster keypair usually restricts access to only root.
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser:  &rootID,
				RunAsGroup: &rootID,
			},
		},
	}
}

func isAgentPodUpToDate(actualAgentPod, expectedAgentPod *corev1.Pod) bool {
	requiredLabelsAllPresentWithCorrectValues := true
	actualLabels := actualAgentPod.ObjectMeta.Labels
	for expectedLabelKey, expectedLabelValue := range expectedAgentPod.ObjectMeta.Labels {
		if actualLabels[expectedLabelKey] != expectedLabelValue {
			requiredLabelsAllPresentWithCorrectValues = false
			break
		}
	}

	if actualAgentPod.Spec.SecurityContext == nil {
		return false
	}

	return requiredLabelsAllPresentWithCorrectValues &&
		equality.Semantic.DeepEqual(
			actualAgentPod.Spec.Containers[0].VolumeMounts,
			expectedAgentPod.Spec.Containers[0].VolumeMounts,
		) &&
		equality.Semantic.DeepEqual(
			actualAgentPod.Spec.Containers[0].Name,
			expectedAgentPod.Spec.Containers[0].Name,
		) &&
		equality.Semantic.DeepEqual(
			actualAgentPod.Spec.Containers[0].Image,
			expectedAgentPod.Spec.Containers[0].Image,
		) &&
		equality.Semantic.DeepEqual(
			actualAgentPod.Spec.Containers[0].Command,
			expectedAgentPod.Spec.Containers[0].Command,
		) &&
		equality.Semantic.DeepEqual(
			actualAgentPod.Spec.Volumes,
			expectedAgentPod.Spec.Volumes,
		) &&
		equality.Semantic.DeepEqual(
			actualAgentPod.Spec.RestartPolicy,
			expectedAgentPod.Spec.RestartPolicy,
		) &&
		equality.Semantic.DeepEqual(
			actualAgentPod.Spec.NodeSelector,
			expectedAgentPod.Spec.NodeSelector,
		) &&
		equality.Semantic.DeepEqual(
			actualAgentPod.Spec.AutomountServiceAccountToken,
			expectedAgentPod.Spec.AutomountServiceAccountToken,
		) &&
		equality.Semantic.DeepEqual(
			actualAgentPod.Spec.NodeName,
			expectedAgentPod.Spec.NodeName,
		) &&
		equality.Semantic.DeepEqual(
			actualAgentPod.Spec.Tolerations,
			expectedAgentPod.Spec.Tolerations,
		) &&
		equality.Semantic.DeepEqual(
			actualAgentPod.Spec.SecurityContext.RunAsUser,
			expectedAgentPod.Spec.SecurityContext.RunAsUser,
		) &&
		equality.Semantic.DeepEqual(
			actualAgentPod.Spec.SecurityContext.RunAsGroup,
			expectedAgentPod.Spec.SecurityContext.RunAsGroup,
		)
}

func isControllerManagerPod(obj metav1.Object) bool {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return false
	}

	if pod.Labels == nil {
		return false
	}

	component, ok := pod.Labels["component"]
	if !ok || component != "kube-controller-manager" {
		return false
	}

	if pod.Status.Phase != corev1.PodRunning {
		return false
	}

	return true
}

func isAgentPod(obj metav1.Object) bool {
	value, foundLabel := obj.GetLabels()[agentPodLabelKey]
	return foundLabel && value == agentPodLabelValue
}

func findControllerManagerPodForSpecificAgentPod(
	agentPod *corev1.Pod,
	kubeSystemPodInformer corev1informers.PodInformer,
) (*corev1.Pod, error) {
	name, ok := agentPod.Annotations[controllerManagerNameAnnotationKey]
	if !ok {
		plog.Debug("agent pod missing parent name annotation", "pod", agentPod.Name)
		return nil, nil
	}

	uid, ok := agentPod.Annotations[controllerManagerUIDAnnotationKey]
	if !ok {
		plog.Debug("agent pod missing parent uid annotation", "pod", agentPod.Name)
		return nil, nil
	}

	maybeControllerManagerPod, err := kubeSystemPodInformer.
		Lister().
		Pods(ControllerManagerNamespace).
		Get(name)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return nil, fmt.Errorf("cannot get controller pod: %w", err)
	} else if notFound ||
		maybeControllerManagerPod == nil ||
		string(maybeControllerManagerPod.UID) != uid {
		return nil, nil
	}

	return maybeControllerManagerPod, nil
}

func strategyError(clock clock.Clock, err error) configv1alpha1.CredentialIssuerStrategy {
	return configv1alpha1.CredentialIssuerStrategy{
		Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
		Status:         configv1alpha1.ErrorStrategyStatus,
		Reason:         configv1alpha1.CouldNotFetchKeyStrategyReason,
		Message:        err.Error(),
		LastUpdateTime: metav1.NewTime(clock.Now()),
	}
}

func hash(controllerManagerPod *corev1.Pod) string {
	// FNV should be faster than SHA, and we don't care about hash-reversibility here, and Kubernetes
	// uses FNV for their pod templates, so should be good enough for us?
	h := fnv.New32a()
	_, _ = h.Write([]byte(controllerManagerPod.UID)) // Never returns an error, per godoc.
	return hex.EncodeToString(h.Sum([]byte{}))
}
