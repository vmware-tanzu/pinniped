/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package issuerconfig

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/suzerain-io/controller-go"
	pinnipedcontroller "github.com/suzerain-io/pinniped/internal/controller"
	crdpinnipedv1alpha1 "github.com/suzerain-io/pinniped/kubernetes/1.19/api/apis/crdpinniped/v1alpha1"
	pinnipedclientset "github.com/suzerain-io/pinniped/kubernetes/1.19/client-go/clientset/versioned"
	crdpinnipedv1alpha1informers "github.com/suzerain-io/pinniped/kubernetes/1.19/client-go/informers/externalversions/crdpinniped/v1alpha1"
)

const (
	ClusterInfoNamespace = "kube-public"

	clusterInfoName         = "cluster-info"
	clusterInfoConfigMapKey = "kubeconfig"

	configName = "pinniped-config"
)

type publisherController struct {
	namespace                      string
	serverOverride                 *string
	pinnipedClient                 pinnipedclientset.Interface
	configMapInformer              corev1informers.ConfigMapInformer
	credentialIssuerConfigInformer crdpinnipedv1alpha1informers.CredentialIssuerConfigInformer
}

func NewPublisherController(
	namespace string,
	serverOverride *string,
	pinnipedClient pinnipedclientset.Interface,
	configMapInformer corev1informers.ConfigMapInformer,
	credentialIssuerConfigInformer crdpinnipedv1alpha1informers.CredentialIssuerConfigInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controller.Controller {
	return controller.New(
		controller.Config{
			Name: "publisher-controller",
			Syncer: &publisherController{
				namespace:                      namespace,
				serverOverride:                 serverOverride,
				pinnipedClient:                 pinnipedClient,
				configMapInformer:              configMapInformer,
				credentialIssuerConfigInformer: credentialIssuerConfigInformer,
			},
		},
		withInformer(
			configMapInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(clusterInfoName, ClusterInfoNamespace),
			controller.InformerOption{},
		),
		withInformer(
			credentialIssuerConfigInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(configName, namespace),
			controller.InformerOption{},
		),
	)
}

func (c *publisherController) Sync(ctx controller.Context) error {
	configMap, err := c.configMapInformer.
		Lister().
		ConfigMaps(ClusterInfoNamespace).
		Get(clusterInfoName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s configmap: %w", clusterInfoName, err)
	}
	if notFound {
		klog.InfoS(
			"could not find config map",
			"configmap",
			klog.KRef(ClusterInfoNamespace, clusterInfoName),
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

	if c.serverOverride != nil {
		server = *c.serverOverride
	}

	existingCredentialIssuerConfigFromInformerCache, err := c.credentialIssuerConfigInformer.
		Lister().
		CredentialIssuerConfigs(c.namespace).
		Get(configName)
	notFound = k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("could not get credentialissuerconfig: %w", err)
	}

	updateServerAndCAFunc := func(c *crdpinnipedv1alpha1.CredentialIssuerConfig) {
		c.Status.KubeConfigInfo = &crdpinnipedv1alpha1.CredentialIssuerConfigKubeConfigInfo{
			Server:                   server,
			CertificateAuthorityData: certificateAuthorityData,
		}
	}
	err = createOrUpdateCredentialIssuerConfig(
		ctx.Context,
		existingCredentialIssuerConfigFromInformerCache,
		notFound,
		configName,
		c.namespace,
		c.pinnipedClient,
		updateServerAndCAFunc)
	return err
}

func CreateOrUpdateCredentialIssuerConfig(
	ctx context.Context,
	credentialIssuerConfigNamespace string,
	pinnipedClient pinnipedclientset.Interface,
	applyUpdatesToCredentialIssuerConfigFunc func(configToUpdate *crdpinnipedv1alpha1.CredentialIssuerConfig),
) error {
	credentialIssuerConfigName := configName

	existingCredentialIssuerConfig, err := pinnipedClient.
		CrdV1alpha1().
		CredentialIssuerConfigs(credentialIssuerConfigNamespace).
		Get(ctx, credentialIssuerConfigName, metav1.GetOptions{})

	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("could not get credentialissuerconfig: %w", err)
	}

	return createOrUpdateCredentialIssuerConfig(
		ctx,
		existingCredentialIssuerConfig,
		notFound,
		credentialIssuerConfigName,
		credentialIssuerConfigNamespace,
		pinnipedClient,
		applyUpdatesToCredentialIssuerConfigFunc)
}

func createOrUpdateCredentialIssuerConfig(
	ctx context.Context,
	existingCredentialIssuerConfig *crdpinnipedv1alpha1.CredentialIssuerConfig,
	notFound bool,
	credentialIssuerConfigName string,
	credentialIssuerConfigNamespace string,
	pinnipedClient pinnipedclientset.Interface,
	applyUpdatesToCredentialIssuerConfigFunc func(configToUpdate *crdpinnipedv1alpha1.CredentialIssuerConfig),
) error {
	credentialIssuerConfigsClient := pinnipedClient.CrdV1alpha1().CredentialIssuerConfigs(credentialIssuerConfigNamespace)

	if notFound {
		// Create it
		credentialIssuerConfig := minimalValidCredentialIssuerConfig(credentialIssuerConfigName, credentialIssuerConfigNamespace)
		applyUpdatesToCredentialIssuerConfigFunc(credentialIssuerConfig)

		if _, err := credentialIssuerConfigsClient.Create(ctx, credentialIssuerConfig, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("could not create credentialissuerconfig: %w", err)
		}
	} else {
		// Already exists, so check to see if we need to update it
		credentialIssuerConfig := existingCredentialIssuerConfig.DeepCopy()
		applyUpdatesToCredentialIssuerConfigFunc(credentialIssuerConfig)

		if reflect.DeepEqual(existingCredentialIssuerConfig.Status, credentialIssuerConfig.Status) {
			// Nothing interesting would change as a result of this update, so skip it
			return nil
		}

		if _, err := credentialIssuerConfigsClient.Update(ctx, credentialIssuerConfig, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("could not update credentialissuerconfig: %w", err)
		}
	}

	return nil
}

func minimalValidCredentialIssuerConfig(
	credentialIssuerConfigName string,
	credentialIssuerConfigNamespace string,
) *crdpinnipedv1alpha1.CredentialIssuerConfig {
	return &crdpinnipedv1alpha1.CredentialIssuerConfig{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      credentialIssuerConfigName,
			Namespace: credentialIssuerConfigNamespace,
		},
		Status: crdpinnipedv1alpha1.CredentialIssuerConfigStatus{
			Strategies:     []crdpinnipedv1alpha1.CredentialIssuerConfigStrategy{},
			KubeConfigInfo: nil,
		},
	}
}
