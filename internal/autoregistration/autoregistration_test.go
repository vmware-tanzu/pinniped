/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package autoregistration

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregationv1fake "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
	"k8s.io/utils/pointer"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		name            string
		input           SetupOptions
		mocks           func(*kubefake.Clientset, *aggregationv1fake.Clientset)
		wantErr         string
		wantServices    []corev1.Service
		wantAPIServices []apiregistrationv1.APIService
	}{
		{
			name: "no such namespace",
			input: SetupOptions{
				Namespace: "foo",
			},
			wantErr: `could not get namespace: namespaces "foo" not found`,
		},
		{
			name: "service template missing port",
			input: SetupOptions{
				Namespace: "test-namespace",
			},
			mocks: func(kube *kubefake.Clientset, agg *aggregationv1fake.Clientset) {
				_ = kube.Tracker().Add(&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "test-namespace", UID: "test-namespace-uid"},
				})
			},
			wantErr: `invalid service template: must have 1 port (found 0)`,
		},
		{
			name: "service template missing port",
			input: SetupOptions{
				Namespace: "test-namespace",
				ServiceTemplate: corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "replaceme",
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Protocol:   "UDP",
								Port:       1234,
								TargetPort: intstr.IntOrString{IntVal: 1234},
							},
						},
					},
				},
			},
			mocks: func(kube *kubefake.Clientset, agg *aggregationv1fake.Clientset) {
				_ = kube.Tracker().Add(&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "test-namespace", UID: "test-namespace-uid"},
				})
			},
			wantErr: `invalid service template: must expose TCP/443 (found UDP/1234)`,
		},
		{
			name: "fail to create service",
			input: SetupOptions{
				Namespace: "test-namespace",
				ServiceTemplate: corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "replaceme",
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Protocol:   "TCP",
								Port:       443,
								TargetPort: intstr.IntOrString{IntVal: 1234},
							},
						},
					},
				},
			},
			mocks: func(kube *kubefake.Clientset, agg *aggregationv1fake.Clientset) {
				_ = kube.Tracker().Add(&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "test-namespace", UID: "test-namespace-uid"},
				})
				kube.PrependReactor("create", "services", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("some Service creation failure")
				})
			},
			wantErr: `could not create service: some Service creation failure`,
		},
		{
			name: "fail to create API service",
			input: SetupOptions{
				Namespace: "test-namespace",
				ServiceTemplate: corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "replaceme",
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Protocol:   "TCP",
								Port:       443,
								TargetPort: intstr.IntOrString{IntVal: 1234},
							},
						},
					},
				},
			},
			mocks: func(kube *kubefake.Clientset, agg *aggregationv1fake.Clientset) {
				_ = kube.Tracker().Add(&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "test-namespace", UID: "test-namespace-uid"},
				})
				agg.PrependReactor("create", "apiservices", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("some APIService creation failure")
				})
			},
			wantErr: `could not create API service: some APIService creation failure`,
		},
		{
			name: "success",
			input: SetupOptions{
				Namespace: "test-namespace",
				ServiceTemplate: corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-service",
						Namespace: "replaceme",
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Protocol:   "TCP",
								Port:       443,
								TargetPort: intstr.IntOrString{IntVal: 1234},
							},
						},
					},
				},
				APIServiceTemplate: apiregistrationv1.APIService{
					ObjectMeta: metav1.ObjectMeta{Name: "test-api-service"},
					Spec: apiregistrationv1.APIServiceSpec{
						Group:                "test-api-group",
						Version:              "test-version",
						CABundle:             []byte("test-ca-bundle"),
						GroupPriorityMinimum: 1234,
						VersionPriority:      4321,
					},
				},
			},
			mocks: func(kube *kubefake.Clientset, agg *aggregationv1fake.Clientset) {
				_ = kube.Tracker().Add(&corev1.Namespace{
					TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
					ObjectMeta: metav1.ObjectMeta{Name: "test-namespace", UID: "test-namespace-uid"},
				})
			},
			wantServices: []corev1.Service{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-service",
					Namespace: "test-namespace",
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Protocol:   "TCP",
							Port:       443,
							TargetPort: intstr.IntOrString{IntVal: 1234},
						},
					},
				},
			}},
			wantAPIServices: []apiregistrationv1.APIService{{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-api-service",
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: "v1",
						Kind:       "Namespace",
						Name:       "test-namespace",
						UID:        "test-namespace-uid",
					}},
				},
				Spec: apiregistrationv1.APIServiceSpec{
					Service: &apiregistrationv1.ServiceReference{
						Namespace: "test-namespace",
						Name:      "test-service",
						Port:      pointer.Int32Ptr(443),
					},
					Group:                "test-api-group",
					Version:              "test-version",
					CABundle:             []byte("test-ca-bundle"),
					GroupPriorityMinimum: 1234,
					VersionPriority:      4321,
				},
			}},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			kubeClient := kubefake.NewSimpleClientset()
			aggregationClient := aggregationv1fake.NewSimpleClientset()
			if tt.mocks != nil {
				tt.mocks(kubeClient, aggregationClient)
			}

			tt.input.CoreV1 = kubeClient.CoreV1()
			tt.input.AggregationV1 = aggregationClient
			err := Setup(context.Background(), tt.input)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.wantServices != nil {
				objects, err := kubeClient.CoreV1().Services(tt.input.Namespace).List(ctx, metav1.ListOptions{})
				require.NoError(t, err)
				require.Equal(t, tt.wantServices, objects.Items)
			}
			if tt.wantAPIServices != nil {
				objects, err := aggregationClient.ApiregistrationV1().APIServices().List(ctx, metav1.ListOptions{})
				require.NoError(t, err)
				require.Equal(t, tt.wantAPIServices, objects.Items)
			}
		})
	}
}

func TestCreateOrUpdateService(t *testing.T) {
	tests := []struct {
		name        string
		input       *corev1.Service
		mocks       func(*kubefake.Clientset)
		wantObjects []corev1.Service
		wantErr     string
	}{
		{
			name: "error on create",
			input: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "ns"},
				Spec: corev1.ServiceSpec{
					Type:      corev1.ServiceTypeClusterIP,
					ClusterIP: "1.2.3.4",
				},
			},
			mocks: func(c *kubefake.Clientset) {
				c.PrependReactor("create", "services", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("error on create")
				})
			},
			wantErr: "could not create service: error on create",
		},
		{
			name: "new",
			input: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "ns"},
				Spec: corev1.ServiceSpec{
					Type:      corev1.ServiceTypeClusterIP,
					ClusterIP: "1.2.3.4",
				},
			},
			wantObjects: []corev1.Service{{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "ns"},
				Spec: corev1.ServiceSpec{
					Type:      corev1.ServiceTypeClusterIP,
					ClusterIP: "1.2.3.4",
				},
			}},
		},
		{
			name: "update",
			mocks: func(c *kubefake.Clientset) {
				_ = c.Tracker().Add(&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "ns"},
					Spec: corev1.ServiceSpec{
						Type:      corev1.ServiceTypeClusterIP,
						ClusterIP: "1.2.3.4",
					},
				})
			},
			input: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "ns"},
				Spec: corev1.ServiceSpec{
					Type:      corev1.ServiceTypeClusterIP,
					ClusterIP: "1.2.3.4",
				},
			},
			wantObjects: []corev1.Service{{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "ns"},
				Spec: corev1.ServiceSpec{
					Type:      corev1.ServiceTypeClusterIP,
					ClusterIP: "1.2.3.4",
				},
			}},
		},
		{
			name: "error on get",
			mocks: func(c *kubefake.Clientset) {
				_ = c.Tracker().Add(&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					Spec: corev1.ServiceSpec{
						Type:      corev1.ServiceTypeClusterIP,
						ClusterIP: "1.2.3.4",
					},
				})
				c.PrependReactor("get", "services", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("error on get")
				})
			},
			input: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: corev1.ServiceSpec{
					Type:      corev1.ServiceTypeClusterIP,
					ClusterIP: "1.2.3.4",
				},
			},
			wantErr: "could not update service: could not get existing version of service: error on get",
		},
		{
			name: "error on get, successful retry",
			mocks: func(c *kubefake.Clientset) {
				_ = c.Tracker().Add(&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					Spec: corev1.ServiceSpec{
						Type:      corev1.ServiceTypeClusterIP,
						ClusterIP: "1.2.3.4",
					},
				})

				hit := false
				c.PrependReactor("get", "services", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					// Return an error on the first call, then fall through to the default (successful) response.
					if !hit {
						hit = true
						return true, nil, fmt.Errorf("error on get")
					}
					return false, nil, nil
				})
			},
			input: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: corev1.ServiceSpec{
					Type:      corev1.ServiceTypeClusterIP,
					ClusterIP: "1.2.3.4",
				},
			},
			wantErr: "could not update service: could not get existing version of service: error on get",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			client := kubefake.NewSimpleClientset()
			if tt.mocks != nil {
				tt.mocks(client)
			}

			err := createOrUpdateService(ctx, client.CoreV1(), tt.input)

			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.wantObjects != nil {
				objects, err := client.CoreV1().Services(tt.input.ObjectMeta.Namespace).List(ctx, metav1.ListOptions{})
				require.NoError(t, err)
				require.Equal(t, tt.wantObjects, objects.Items)
			}
		})
	}
}

func TestCreateOrUpdateAPIService(t *testing.T) {
	tests := []struct {
		name        string
		input       *apiregistrationv1.APIService
		mocks       func(*aggregationv1fake.Clientset)
		wantObjects []apiregistrationv1.APIService
		wantErr     string
	}{
		{
			name: "error on create",
			input: &apiregistrationv1.APIService{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: apiregistrationv1.APIServiceSpec{
					GroupPriorityMinimum: 123,
					VersionPriority:      456,
				},
			},
			mocks: func(c *aggregationv1fake.Clientset) {
				c.PrependReactor("create", "apiservices", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("error on create")
				})
			},
			wantErr: "could not create API service: error on create",
		},
		{
			name: "new",
			input: &apiregistrationv1.APIService{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: apiregistrationv1.APIServiceSpec{
					GroupPriorityMinimum: 123,
					VersionPriority:      456,
				},
			},
			wantObjects: []apiregistrationv1.APIService{{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: apiregistrationv1.APIServiceSpec{
					GroupPriorityMinimum: 123,
					VersionPriority:      456,
				},
			}},
		},
		{
			name: "update",
			mocks: func(c *aggregationv1fake.Clientset) {
				_ = c.Tracker().Add(&apiregistrationv1.APIService{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					Spec: apiregistrationv1.APIServiceSpec{
						GroupPriorityMinimum: 999,
						VersionPriority:      999,
					},
				})
			},
			input: &apiregistrationv1.APIService{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: apiregistrationv1.APIServiceSpec{
					GroupPriorityMinimum: 123,
					VersionPriority:      456,
				},
			},
			wantObjects: []apiregistrationv1.APIService{{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: apiregistrationv1.APIServiceSpec{
					GroupPriorityMinimum: 123,
					VersionPriority:      456,
				},
			}},
		},
		{
			name: "error on get",
			mocks: func(c *aggregationv1fake.Clientset) {
				_ = c.Tracker().Add(&apiregistrationv1.APIService{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					Spec: apiregistrationv1.APIServiceSpec{
						GroupPriorityMinimum: 999,
						VersionPriority:      999,
					},
				})
				c.PrependReactor("get", "apiservices", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("error on get")
				})
			},
			input: &apiregistrationv1.APIService{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: apiregistrationv1.APIServiceSpec{
					GroupPriorityMinimum: 123,
					VersionPriority:      456,
				},
			},
			wantErr: "could not update API service: could not get existing version of API service: error on get",
		},
		{
			name: "error on get, successful retry",
			mocks: func(c *aggregationv1fake.Clientset) {
				_ = c.Tracker().Add(&apiregistrationv1.APIService{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					Spec: apiregistrationv1.APIServiceSpec{
						GroupPriorityMinimum: 999,
						VersionPriority:      999,
					},
				})

				hit := false
				c.PrependReactor("get", "apiservices", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					// Return an error on the first call, then fall through to the default (successful) response.
					if !hit {
						hit = true
						return true, nil, fmt.Errorf("error on get")
					}
					return false, nil, nil
				})
			},
			input: &apiregistrationv1.APIService{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				Spec: apiregistrationv1.APIServiceSpec{
					GroupPriorityMinimum: 123,
					VersionPriority:      456,
				},
			},
			wantErr: "could not update API service: could not get existing version of API service: error on get",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			client := aggregationv1fake.NewSimpleClientset()
			if tt.mocks != nil {
				tt.mocks(client)
			}

			err := createOrUpdateAPIService(ctx, client, tt.input)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.wantObjects != nil {
				objects, err := client.ApiregistrationV1().APIServices().List(ctx, metav1.ListOptions{})
				require.NoError(t, err)
				require.Equal(t, tt.wantObjects, objects.Items)
			}
		})
	}
}
