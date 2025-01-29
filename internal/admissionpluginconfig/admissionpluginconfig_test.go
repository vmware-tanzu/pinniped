// Copyright 2024-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package admissionpluginconfig

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/discovery"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	kubetesting "k8s.io/client-go/testing"
)

func TestValidateAdmissionPluginNames(t *testing.T) {
	tests := []struct {
		name        string
		pluginNames []string
		wantErr     string
	}{
		{
			name:        "empty",
			pluginNames: []string{},
		},
		{
			name: "all current valid values (this list may change in future versions of Kubernetes packages)",
			pluginNames: []string{
				"NamespaceLifecycle",
				"MutatingAdmissionWebhook",
				"ValidatingAdmissionPolicy",
				"ValidatingAdmissionWebhook",
			},
		},
		{
			name: "one invalid value",
			pluginNames: []string{
				"NamespaceLifecycle",
				"MutatingAdmissionWebhook",
				"ValidatingAdmissionPolicy",
				"foobar",
				"ValidatingAdmissionWebhook",
			},
			wantErr: "admission plugin names not recognized: [foobar] (each must be one of [NamespaceLifecycle MutatingAdmissionPolicy MutatingAdmissionWebhook ValidatingAdmissionPolicy ValidatingAdmissionWebhook])",
		},
		{
			name: "multiple invalid values",
			pluginNames: []string{
				"NamespaceLifecycle",
				"MutatingAdmissionWebhook",
				"foobat",
				"ValidatingAdmissionPolicy",
				"foobar",
				"ValidatingAdmissionWebhook",
				"foobaz",
			},
			wantErr: "admission plugin names not recognized: [foobat foobar foobaz] (each must be one of [NamespaceLifecycle MutatingAdmissionPolicy MutatingAdmissionWebhook ValidatingAdmissionPolicy ValidatingAdmissionWebhook])",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateAdmissionPluginNames(tt.pluginNames)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfigureAdmissionPlugins(t *testing.T) {
	coreResources := &metav1.APIResourceList{
		GroupVersion: corev1.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: "pods", Namespaced: true, Kind: "Pod"},
		},
	}

	appsResources := &metav1.APIResourceList{
		GroupVersion: appsv1.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: "deployments", Namespaced: true, Kind: "Deployment"},
			{Name: "deployments/scale", Namespaced: true, Kind: "Scale", Group: "apps", Version: "v1"},
		},
	}

	newStyleAdmissionResourcesWithValidatingAdmissionPolicies := &metav1.APIResourceList{
		GroupVersion: admissionregistrationv1.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: "validatingwebhookconfigurations", Kind: "ValidatingWebhookConfiguration"},
			{Name: "validatingadmissionpolicies", Kind: "ValidatingAdmissionPolicy"},
		},
	}

	newStyleAdmissionResourcesWithValidatingAdmissionPoliciesAtOlderAPIVersion := &metav1.APIResourceList{
		GroupVersion: admissionregistrationv1.SchemeGroupVersion.Group + "/v1beta1",
		APIResources: []metav1.APIResource{
			{Name: "validatingwebhookconfigurations", Kind: "ValidatingWebhookConfiguration"},
			{Name: "validatingadmissionpolicies", Kind: "ValidatingAdmissionPolicy"},
		},
	}

	oldStyleAdmissionResourcesWithoutValidatingAdmissionPolicies := &metav1.APIResourceList{
		GroupVersion: admissionregistrationv1.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: "validatingwebhookconfigurations", Kind: "ValidatingWebhookConfiguration"},
		},
	}

	tests := []struct {
		name                  string
		disabledPlugins       []string
		availableAPIResources []*metav1.APIResourceList
		discoveryErr          error
		wantErr               string
		wantDisabledPlugins   []string
	}{
		{
			name: "when there is a ValidatingAdmissionPolicy resource and nil disabled list, then we do not change the plugin configuration",
			availableAPIResources: []*metav1.APIResourceList{
				coreResources,
				newStyleAdmissionResourcesWithValidatingAdmissionPolicies,
				appsResources,
			},
			disabledPlugins:     nil,
			wantDisabledPlugins: nil,
		},
		{
			name: "when there is a ValidatingAdmissionPolicy resource and empty disabled list, then we do not change the plugin configuration",
			availableAPIResources: []*metav1.APIResourceList{
				coreResources,
				newStyleAdmissionResourcesWithValidatingAdmissionPolicies,
				appsResources,
			},
			disabledPlugins:     []string{},
			wantDisabledPlugins: nil,
		},
		{
			name: "when there is no ValidatingAdmissionPolicy resource, as there would not be in an old Kubernetes cluster, then we disable that admission plugin",
			availableAPIResources: []*metav1.APIResourceList{
				coreResources,
				oldStyleAdmissionResourcesWithoutValidatingAdmissionPolicies,
				appsResources,
			},
			disabledPlugins:     nil,
			wantDisabledPlugins: []string{"ValidatingAdmissionPolicy"},
		},
		{
			name: "when there is only an older version of ValidatingAdmissionPolicy resource, as there would be in an old Kubernetes cluster with the feature flag enabled, then we disable that plugin (because the admission code wants to watch v1)",
			availableAPIResources: []*metav1.APIResourceList{
				coreResources,
				newStyleAdmissionResourcesWithValidatingAdmissionPoliciesAtOlderAPIVersion,
				appsResources,
			},
			disabledPlugins:     []string{},
			wantDisabledPlugins: []string{"ValidatingAdmissionPolicy"},
		},
		{
			name:                  "when there is no ValidatingAdmissionPolicy resource, and the ValidatingAdmissionPolicy plugin was explicitly disabled, then do not perform discovery, and just disable it",
			availableAPIResources: []*metav1.APIResourceList{},
			discoveryErr:          errors.New("total error from API discovery client"),
			disabledPlugins:       []string{"MutatingAdmissionWebhook", "ValidatingAdmissionPolicy"},
			wantDisabledPlugins:   []string{"MutatingAdmissionWebhook", "ValidatingAdmissionPolicy"},
		},
		{
			name: "when there is no ValidatingAdmissionPolicy resource, and the ValidatingAdmissionPolicy plugin was not explicitly disabled, still disable it",
			availableAPIResources: []*metav1.APIResourceList{
				coreResources,
				oldStyleAdmissionResourcesWithoutValidatingAdmissionPolicies,
				appsResources,
			},
			disabledPlugins:     []string{"MutatingAdmissionWebhook", "NamespaceLifecycle"},
			wantDisabledPlugins: []string{"MutatingAdmissionWebhook", "NamespaceLifecycle", "ValidatingAdmissionPolicy"},
		},
		{
			name:                "when there is a total error returned by discovery",
			discoveryErr:        errors.New("total error from API discovery client"),
			wantErr:             "failed looking up availability of ValidatingAdmissionPolicy resource: failed to perform k8s API discovery: total error from API discovery client",
			wantDisabledPlugins: nil,
		},
		{
			name: "when there is a partial error returned by discovery which does include the group of interest, then we cannot ignore the error, because we could not discover anything about that group",
			availableAPIResources: []*metav1.APIResourceList{
				coreResources,
				oldStyleAdmissionResourcesWithoutValidatingAdmissionPolicies,
				appsResources,
			},
			discoveryErr: &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{
				schema.GroupVersion{Group: "someGroup", Version: "v1"}:                    errors.New("fake error for someGroup"),
				schema.GroupVersion{Group: "admissionregistration.k8s.io", Version: "v1"}: errors.New("fake error for admissionregistration"),
			}},
			wantErr:             "failed looking up availability of ValidatingAdmissionPolicy resource: unable to retrieve the complete list of server APIs: admissionregistration.k8s.io/v1: fake error for admissionregistration, someGroup/v1: fake error for someGroup",
			wantDisabledPlugins: nil,
		},
		{
			name: "when there is a partial error returned by discovery on an new-style cluster which does not include the group of interest, then we can ignore the error and use the default plugins",
			availableAPIResources: []*metav1.APIResourceList{
				coreResources,
				newStyleAdmissionResourcesWithValidatingAdmissionPolicies,
				appsResources,
			},
			discoveryErr: &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{
				schema.GroupVersion{Group: "someGroup", Version: "v1"}:      errors.New("fake error for someGroup"),
				schema.GroupVersion{Group: "someOtherGroup", Version: "v1"}: errors.New("fake error for someOtherGroup"),
			}},
			wantDisabledPlugins: nil,
		},
		{
			name: "when there is a partial error returned by discovery on an old-style cluster which does not include the group of interest, then we can ignore the error and customize the plugins",
			availableAPIResources: []*metav1.APIResourceList{
				coreResources,
				oldStyleAdmissionResourcesWithoutValidatingAdmissionPolicies,
				appsResources,
			},
			discoveryErr: &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{
				schema.GroupVersion{Group: "someGroup", Version: "v1"}:      errors.New("fake error for someGroup"),
				schema.GroupVersion{Group: "someOtherGroup", Version: "v1"}: errors.New("fake error for someOtherGroup"),
			}},
			wantDisabledPlugins: []string{"ValidatingAdmissionPolicy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kubeClient := kubernetesfake.NewSimpleClientset()
			kubeClient.Fake.Resources = tt.availableAPIResources

			// Unfortunately, kubernetesfake.NewSimpleClientset() does not support using reactors to
			// cause discovery to return errors. Instead, we will make our own fake implementation of the
			// discovery client's interface and only mock the parts that we need for this test.
			discoveryClient := newFakeDiscoveryClient(kubeClient)

			if tt.discoveryErr != nil {
				kubeClient.PrependReactor(
					"get",
					"resource",
					func(a kubetesting.Action) (bool, runtime.Object, error) {
						return true, nil, tt.discoveryErr
					},
				)
			}

			opts := &options.RecommendedOptions{
				Admission: options.NewAdmissionOptions(),
			}
			// Sanity checks on opts before we use it.
			require.Empty(t, opts.Admission.DisablePlugins)

			// Call the function under test.
			err := configureAdmissionPlugins(discoveryClient, opts, tt.disabledPlugins)

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.wantErr)
			}

			// Check the expected side effects of the function under test, if any.
			require.Equal(t, tt.wantDisabledPlugins, opts.Admission.DisablePlugins)
		})
	}
}

type fakeDiscoveryClient struct {
	fakeClientSet *kubernetesfake.Clientset
}

var _ discovery.ServerResourcesInterface = &fakeDiscoveryClient{}

func newFakeDiscoveryClient(fakeClientSet *kubernetesfake.Clientset) *fakeDiscoveryClient {
	return &fakeDiscoveryClient{
		fakeClientSet: fakeClientSet,
	}
}

// This is the only function from the discovery.DiscoveryInterface that we care to fake for this test.
// The rest of the functions are here only to satisfy the interface.
func (f *fakeDiscoveryClient) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	action := k8stesting.ActionImpl{
		Verb:     "get",
		Resource: schema.GroupVersionResource{Resource: "resource"},
	}
	// Wire in actions just enough that we can cause errors for the test when we want them.
	// Ignoring the first return value because we don't need it for this test.
	_, err := f.fakeClientSet.Invokes(action, nil)
	// Still return the "partial" results even where there was an error, similar enough to how the real API works.
	return f.fakeClientSet.Resources, err
}

func (f *fakeDiscoveryClient) ServerResourcesForGroupVersion(_ string) (*metav1.APIResourceList, error) {
	return nil, nil
}

func (f *fakeDiscoveryClient) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	return nil, nil, nil
}

func (f *fakeDiscoveryClient) ServerPreferredNamespacedResources() ([]*metav1.APIResourceList, error) {
	return nil, nil
}
