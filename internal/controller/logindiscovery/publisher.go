/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package logindiscovery

import (
	"context"
	"encoding/base64"
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/suzerain-io/controller-go"
	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	placeholderclientset "github.com/suzerain-io/placeholder-name-client-go/pkg/generated/clientset/versioned"
)

const (
	clusterInfoName         = "cluster-info"
	clusterInfoNamespace    = "kube-public"
	clusterInfoConfigMapKey = "kubeconfig"

	configName = "placeholder-name-config"
)

type publisherController struct {
	namespace         string
	kubeClient        kubernetes.Interface
	placeholderClient placeholderclientset.Interface
}

func NewPublisherController(namespace string, kubeClient kubernetes.Interface, placeholderClient placeholderclientset.Interface) controller.Controller {
	return controller.New(
		controller.Config{
			Name: "publisher-controller",
			Syncer: &publisherController{
				namespace:         namespace,
				kubeClient:        kubeClient,
				placeholderClient: placeholderClient,
			},
		},
	)
}

func (c *publisherController) Sync(ctx controller.Context) error {
	configMap, err := c.kubeClient.
		CoreV1().
		ConfigMaps(clusterInfoNamespace).
		Get(ctx.Context, clusterInfoName, metav1.GetOptions{})
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s configmap: %w", clusterInfoName, err)
	}
	if notFound {
		klog.InfoS(
			"could not find config map",
			"configmap",
			klog.KRef(clusterInfoNamespace, clusterInfoName),
		)
		return nil
	}

	kubeConfig, kubeConfigPresent := configMap.Data[clusterInfoConfigMapKey]
	if !kubeConfigPresent {
		klog.InfoS("could not find kubeconfig configmap key")
		return nil
	}

	config, _ := clientcmd.Load([]byte(kubeConfig))

	var certificateAuthorityData, server string
	for _, v := range config.Clusters {
		certificateAuthorityData = base64.StdEncoding.EncodeToString(v.CertificateAuthorityData)
		server = v.Server
		break
	}

	discoveryConfig := placeholderv1alpha1.LoginDiscoveryConfig{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      configName,
			Namespace: c.namespace,
		},
		Spec: placeholderv1alpha1.LoginDiscoveryConfigSpec{
			Server:                   server,
			CertificateAuthorityData: certificateAuthorityData,
		},
	}
	if err := c.createOrUpdateLoginDiscoveryConfig(ctx.Context, &discoveryConfig); err != nil {
		return err
	}

	return nil
}

func (c *publisherController) createOrUpdateLoginDiscoveryConfig(
	ctx context.Context,
	discoveryConfig *placeholderv1alpha1.LoginDiscoveryConfig,
) error {
	loginDiscoveryConfigs := c.placeholderClient.
		PlaceholderV1alpha1().
		LoginDiscoveryConfigs(c.namespace)

	existingDiscoveryConfig, err := loginDiscoveryConfigs.Get(
		ctx,
		discoveryConfig.Name,
		metav1.GetOptions{},
	)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("could not get logindiscoveryconfig: %w", err)
	}

	if notFound {
		if _, err := loginDiscoveryConfigs.Create(
			ctx,
			discoveryConfig,
			metav1.CreateOptions{},
		); err != nil {
			return fmt.Errorf("could not create logindiscoveryconfig: %w", err)
		}
	} else if !equal(existingDiscoveryConfig, discoveryConfig) {
		// Update just the fields we care about.
		existingDiscoveryConfig.Spec.Server = discoveryConfig.Spec.Server
		existingDiscoveryConfig.Spec.CertificateAuthorityData = discoveryConfig.Spec.CertificateAuthorityData

		if _, err := loginDiscoveryConfigs.Update(
			ctx,
			existingDiscoveryConfig,
			metav1.UpdateOptions{},
		); err != nil {
			return fmt.Errorf("could not update logindiscoveryconfig: %w", err)
		}
	}

	return nil
}

func equal(a, b *placeholderv1alpha1.LoginDiscoveryConfig) bool {
	return a.Spec.Server == b.Spec.Server &&
		a.Spec.CertificateAuthorityData == b.Spec.CertificateAuthorityData
}
