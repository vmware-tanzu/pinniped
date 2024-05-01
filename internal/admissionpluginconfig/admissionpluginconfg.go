// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package admissionpluginconfig

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/namespace/lifecycle"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/mutating"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/validating"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/discovery"

	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/plog"
)

// ConfigureAdmissionPlugins may choose to reconfigure the admission plugins present on the given
// RecommendedOptions by mutating it.
//
// The ValidatingAdmissionPolicy feature gate became enabled by default in Kube 1.30.
// When Pinniped is compiled using the Kube 1.30+ libraries, and when installed onto a Kube cluster older than 1.30,
// then the new admission ValidatingAdmissionPolicy plugin prevents all our aggregated APIs from working, seemingly
// because it fails to sync informers created for watching the related resources. As a workaround, ask the k8s API
// server if it has the ValidatingAdmissionPolicy resource, and configure our admission plugins accordingly.
func ConfigureAdmissionPlugins(recommendedOptions *options.RecommendedOptions) error {
	k8sClient, err := kubeclient.New()
	if err != nil {
		return fmt.Errorf("failed to create kube client: %w", err)
	}
	return configureAdmissionPlugins(k8sClient.Kubernetes.Discovery(), recommendedOptions)
}

// configureAdmissionPlugins is the same as ConfigureAdmissionPlugins but allows client injection for unit testing.
func configureAdmissionPlugins(discoveryClient discovery.ServerResourcesInterface, recommendedOptions *options.RecommendedOptions) error {
	// Check if the API server has such a resource.
	hasValidatingAdmissionPolicyResource, err := k8sAPIServerHasValidatingAdmissionPolicyResource(discoveryClient)
	if err != nil {
		return fmt.Errorf("failed looking up availability of ValidatingAdmissionPolicy resource: %w", err)
	}

	if hasValidatingAdmissionPolicyResource {
		// Accept the default admission plugin configuration without any further modification.
		return nil
	}

	// Customize the admission plugins to avoid using the new ValidatingAdmissionPolicy plugin.
	plog.Warning("could not find ValidatingAdmissionPolicy resource on this Kubernetes cluster " +
		"(which is normal for clusters older than Kubernetes 1.30); " +
		"disabling ValidatingAdmissionPolicy admission plugins for all Pinniped aggregated API resource types")

	mutateOptionsToUseOldStyleAdmissionPlugins(recommendedOptions)

	return nil
}

func k8sAPIServerHasValidatingAdmissionPolicyResource(discoveryClient discovery.ServerResourcesInterface) (bool, error) {
	// Perform discovery. We are looking for ValidatingAdmissionPolicy in group
	// admissionregistration.k8s.io at any version.
	resources, err := discoveryClient.ServerPreferredResources()
	partialErr := &discovery.ErrGroupDiscoveryFailed{}
	if resources != nil && errors.As(err, &partialErr) {
		// This is a partial discovery error, most likely caused by Pinniped's own aggregated APIs
		// not being ready yet since this Pinniped pod is typically in the process of starting up
		// when this code is reached. Check if the group that we care about is in the error's list
		// of failed API groups.
		for groupVersion := range partialErr.Groups {
			if groupVersion.Group == admissionregistrationv1.GroupName {
				// There was an error for the specific group that we are trying to find, so
				// return an error. If we don't arrive here, then it must have been error(s) for
				// some other group(s) that we are not looking for, so we can ignore those error(s).
				return false, err
			}
		}
	} else if err != nil {
		// We got some other type of error aside from a partial failure.
		return false, fmt.Errorf("failed to perform k8s API discovery: %w", err)
	}

	// Now look at all discovered groups until we find admissionregistration.k8s.io.
	wantedGroupWithSlash := fmt.Sprintf("%s/", admissionregistrationv1.GroupName)
	for _, resourcesPerGV := range resources {
		if strings.HasPrefix(resourcesPerGV.GroupVersion, wantedGroupWithSlash) {
			// Found the group, so now look to see if it includes ValidatingAdmissionPolicy as a resource,
			// which went GA in Kubernetes 1.30, and could be enabled by a feature flag in previous versions.
			for _, resource := range resourcesPerGV.APIResources {
				if resource.Kind == "ValidatingAdmissionPolicy" {
					// Found it!
					plog.Info("found ValidatingAdmissionPolicy resource on this Kubernetes cluster",
						"group", resource.Group, "version", resource.Version, "kind", resource.Kind)
					return true, nil
				}
			}
		}
	}

	// Didn't findValidatingAdmissionPolicy on this cluster.
	return false, nil
}

func mutateOptionsToUseOldStyleAdmissionPlugins(recommendedOptions *options.RecommendedOptions) {
	plugins := admission.NewPlugins()

	// These lines are copied from server.RegisterAllAdmissionPlugins in k8s.io/apiserver@v0.30.0/pkg/server/plugins.go.
	lifecycle.Register(plugins)
	validating.Register(plugins)
	mutating.Register(plugins)
	// Note that we are not adding this one:
	// validatingadmissionpolicy.Register(newAdmissionPlugins)

	// This list is copied from the implementation of NewAdmissionOptions() in k8s.io/apiserver@v0.30.0/pkg/server/options/admission.go
	recommendedOptions.Admission.RecommendedPluginOrder = []string{
		lifecycle.PluginName,
		mutating.PluginName,
		// Again, note that we are not adding this one:
		// validatingadmissionpolicy.PluginName,
		validating.PluginName,
	}

	// Overwrite the registered plugins with our new, smaller list.
	recommendedOptions.Admission.Plugins = plugins
}
