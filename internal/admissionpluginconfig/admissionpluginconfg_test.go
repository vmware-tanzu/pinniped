// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package admissionpluginconfig

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/discovery"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	kubetesting "k8s.io/client-go/testing"
)

func TestConfigureAdmissionPlugins(t *testing.T) {
	defaultPlugins := admission.NewPlugins()
	defaultPlugins.Register("fake-plugin1", func(config io.Reader) (admission.Interface, error) { return nil, nil })
	defaultPlugins.Register("fake-plugin2", func(config io.Reader) (admission.Interface, error) { return nil, nil })

	defaultPluginsRegistered := []string{"fake-plugin1", "fake-plugin2"}
	defaultRecommendedPluginOrder := []string{"fake-plugin2", "fake-plugin1"}

	customOldStylePluginsRegistered := []string{"MutatingAdmissionWebhook", "NamespaceLifecycle", "ValidatingAdmissionWebhook"}
	customOldStyleRecommendedPluginOrder := []string{"NamespaceLifecycle", "MutatingAdmissionWebhook", "ValidatingAdmissionWebhook"}

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

	oldStyleAdmissionResourcesWithoutValidatingAdmissionPolicies := &metav1.APIResourceList{
		GroupVersion: admissionregistrationv1.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{
			{Name: "validatingwebhookconfigurations", Kind: "ValidatingWebhookConfiguration"},
		},
	}

	tests := []struct {
		name                       string
		availableAPIResources      []*metav1.APIResourceList
		discoveryErr               error
		wantErr                    string
		wantRegisteredPlugins      []string
		wantRecommendedPluginOrder []string
	}{
		{
			name: "when there is a ValidatingAdmissionPolicy resource, then we do not change the plugin configuration",
			availableAPIResources: []*metav1.APIResourceList{
				coreResources,
				newStyleAdmissionResourcesWithValidatingAdmissionPolicies,
				appsResources,
			},
			wantRegisteredPlugins:      defaultPluginsRegistered,
			wantRecommendedPluginOrder: defaultRecommendedPluginOrder,
		},
		{
			name: "when there is no ValidatingAdmissionPolicy resource, as there would not be in an old Kubernetes cluster, then we change the plugin configuration to be more like it was for old versions of Kubernetes",
			availableAPIResources: []*metav1.APIResourceList{
				coreResources,
				oldStyleAdmissionResourcesWithoutValidatingAdmissionPolicies,
				appsResources,
			},
			wantRegisteredPlugins:      customOldStylePluginsRegistered,
			wantRecommendedPluginOrder: customOldStyleRecommendedPluginOrder,
		},
		{
			name:                       "when there is a total error returned by discovery",
			discoveryErr:               errors.New("total error from API discovery client"),
			wantErr:                    "failed looking up availability of ValidatingAdmissionPolicy resource: failed to perform k8s API discovery: total error from API discovery client",
			wantRegisteredPlugins:      defaultPluginsRegistered,
			wantRecommendedPluginOrder: defaultRecommendedPluginOrder,
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
			wantErr:                    "failed looking up availability of ValidatingAdmissionPolicy resource: unable to retrieve the complete list of server APIs: admissionregistration.k8s.io/v1: fake error for admissionregistration, someGroup/v1: fake error for someGroup",
			wantRegisteredPlugins:      defaultPluginsRegistered,
			wantRecommendedPluginOrder: defaultRecommendedPluginOrder,
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
			wantRegisteredPlugins:      defaultPluginsRegistered,
			wantRecommendedPluginOrder: defaultRecommendedPluginOrder,
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
			wantRegisteredPlugins:      customOldStylePluginsRegistered,
			wantRecommendedPluginOrder: customOldStyleRecommendedPluginOrder,
		},
	}

	for _, tt := range tests {
		tt := tt
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
				Admission: &options.AdmissionOptions{
					Plugins:                defaultPlugins,
					RecommendedPluginOrder: defaultRecommendedPluginOrder,
				},
			}
			// Sanity checks on opts before we use it.
			require.Equal(t, defaultPlugins, opts.Admission.Plugins)
			require.Equal(t, defaultPluginsRegistered, opts.Admission.Plugins.Registered())
			require.Equal(t, defaultRecommendedPluginOrder, opts.Admission.RecommendedPluginOrder)

			// Call the function under test.
			err := configureAdmissionPlugins(discoveryClient, opts)

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.wantErr)
			}

			// Check the expected side effects of the function under test, if any.
			require.Equal(t, tt.wantRegisteredPlugins, opts.Admission.Plugins.Registered())
			require.Equal(t, tt.wantRecommendedPluginOrder, opts.Admission.RecommendedPluginOrder)
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
