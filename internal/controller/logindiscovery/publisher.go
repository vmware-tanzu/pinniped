/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package logindiscovery

import (
	"encoding/base64"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

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
	configMap, _ := c.kubeClient.CoreV1().ConfigMaps(clusterInfoNamespace).Get(ctx.Context, clusterInfoName, metav1.GetOptions{})
	kubeConfig := configMap.Data[clusterInfoConfigMapKey] // TODO also handle when the key is not found

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
	_, _ = c.placeholderClient.
		PlaceholderV1alpha1().
		LoginDiscoveryConfigs(c.namespace).
		Create(ctx.Context, &discoveryConfig, metav1.CreateOptions{})

	return nil
}
