/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/suzerain-io/pinniped/pkg/config/api"
)

// NewWebhook creates a webhook from the provided API server url and caBundle
// used to validate TLS connections.
func NewWebhook(spec api.WebhookConfigSpec) (*webhook.WebhookTokenAuthenticator, error) {
	kubeconfig, err := ioutil.TempFile("", "pinniped-webhook-kubeconfig-*")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(kubeconfig.Name())

	if err := anonymousKubeconfig(spec.URL, spec.CABundle, kubeconfig); err != nil {
		return nil, fmt.Errorf("anonymous kubeconfig: %w", err)
	}

	// We use v1beta1 instead of v1 since v1beta1 is more prevalent in our desired
	// integration points.
	version := authenticationv1beta1.SchemeGroupVersion.Version

	// At the current time, we don't provide any audiences because we simply don't
	// have any requirements to do so. This can be changed in the future as
	// requirements change.
	var implicitAuds authenticator.Audiences

	// We set this to nil because we would only need this to support some of the
	// custom proxy stuff used by the API server.
	var customDial utilnet.DialFunc

	return webhook.New(kubeconfig.Name(), version, implicitAuds, customDial)
}

// anonymousKubeconfig writes a kubeconfig file to the provided io.Writer that
// will "use" anonymous auth to talk to a Kube API server at the provided url
// with the provided caBundle.
func anonymousKubeconfig(url string, caBundle []byte, out io.Writer) error {
	config := clientcmdapi.NewConfig()
	config.Clusters["anonymous-cluster"] = &clientcmdapi.Cluster{
		Server:                   url,
		CertificateAuthorityData: caBundle,
	}
	config.Contexts["anonymous"] = &clientcmdapi.Context{
		Cluster: "anonymous-cluster",
	}
	config.CurrentContext = "anonymous"

	data, err := clientcmd.Write(*config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if _, err := out.Write(data); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}
