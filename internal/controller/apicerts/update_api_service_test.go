// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apicerts

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubetesting "k8s.io/client-go/testing"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregatorv1fake "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"

	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
)

func TestUpdateAPIService(t *testing.T) {
	const apiServiceName = "v1alpha1.login.concierge.pinniped.dev"

	tests := []struct {
		name             string
		mocks            func(*aggregatorv1fake.Clientset)
		caInput          []byte
		serviceNamespace string
		wantObjects      []apiregistrationv1.APIService
		wantErr          string
	}{
		{
			name: "happy path update when the pre-existing APIService did not already have a CA bundle",
			mocks: func(c *aggregatorv1fake.Clientset) {
				_ = c.Tracker().Add(&apiregistrationv1.APIService{
					ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
					Spec: apiregistrationv1.APIServiceSpec{
						GroupPriorityMinimum: 999,
						CABundle:             nil,
					},
				})
			},
			caInput: []byte("some-ca-bundle"),
			wantObjects: []apiregistrationv1.APIService{{
				ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
				Spec: apiregistrationv1.APIServiceSpec{
					GroupPriorityMinimum: 999,
					CABundle:             []byte("some-ca-bundle"),
				},
			}},
		},
		{
			name: "happy path update when the pre-existing APIService already had a CA bundle",
			mocks: func(c *aggregatorv1fake.Clientset) {
				_ = c.Tracker().Add(&apiregistrationv1.APIService{
					ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
					Spec: apiregistrationv1.APIServiceSpec{
						GroupPriorityMinimum: 999,
						CABundle:             []byte("some-other-different-ca-bundle"),
					},
				})
			},
			caInput: []byte("some-ca-bundle"),
			wantObjects: []apiregistrationv1.APIService{{
				ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
				Spec: apiregistrationv1.APIServiceSpec{
					GroupPriorityMinimum: 999,
					CABundle:             []byte("some-ca-bundle"),
				},
			}},
		},
		{
			name: "happy path update when the pre-existing APIService already has the same CA bundle so there is no need to update",
			mocks: func(c *aggregatorv1fake.Clientset) {
				_ = c.Tracker().Add(&apiregistrationv1.APIService{
					ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
					Spec: apiregistrationv1.APIServiceSpec{
						GroupPriorityMinimum: 999,
						CABundle:             []byte("some-ca-bundle"),
					},
				})
				c.PrependReactor("update", "apiservices", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("should not encounter this error because update should be skipped in this case")
				})
			},
			caInput: []byte("some-ca-bundle"),
			wantObjects: []apiregistrationv1.APIService{{
				ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
				Spec: apiregistrationv1.APIServiceSpec{
					GroupPriorityMinimum: 999,
					CABundle:             []byte("some-ca-bundle"), // unchanged
				},
			}},
		},
		{
			name: "skip update when there is another pinniped instance",
			mocks: func(c *aggregatorv1fake.Clientset) {
				_ = c.Tracker().Add(&apiregistrationv1.APIService{
					ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
					Spec: apiregistrationv1.APIServiceSpec{
						GroupPriorityMinimum: 999,
						CABundle:             []byte("some-other-different-ca-bundle"),
						Service: &apiregistrationv1.ServiceReference{
							Namespace: "namespace-2",
						},
					},
				})
				c.PrependReactor("update", "apiservices", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("should not encounter this error because update should be skipped in this case")
				})
			},
			caInput:          []byte("some-ca-bundle"),
			serviceNamespace: "namespace-1",
			wantObjects: []apiregistrationv1.APIService{{
				ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
				Spec: apiregistrationv1.APIServiceSpec{
					GroupPriorityMinimum: 999,
					CABundle:             []byte("some-other-different-ca-bundle"), // unchanged
					Service: &apiregistrationv1.ServiceReference{
						Namespace: "namespace-2",
					},
				},
			}},
		},
		{
			name: "error on update",
			mocks: func(c *aggregatorv1fake.Clientset) {
				_ = c.Tracker().Add(&apiregistrationv1.APIService{
					ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
					Spec: apiregistrationv1.APIServiceSpec{
						GroupPriorityMinimum: 999,
						CABundle:             []byte("some-other-different-ca-bundle"),
					},
				})
				c.PrependReactor("update", "apiservices", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("error on update")
				})
			},
			caInput: []byte("some-ca-bundle"),
			wantErr: "could not update API service: error on update",
		},
		{
			name: "error on get",
			mocks: func(c *aggregatorv1fake.Clientset) {
				_ = c.Tracker().Add(&apiregistrationv1.APIService{
					ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
					Spec:       apiregistrationv1.APIServiceSpec{},
				})
				c.PrependReactor("get", "apiservices", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("error on get")
				})
			},
			caInput: []byte("some-ca-bundle"),
			wantErr: "could not update API service: could not get existing version of API service: error on get",
		},
		{
			name: "conflict error on update, followed by successful retry",
			mocks: func(c *aggregatorv1fake.Clientset) {
				_ = c.Tracker().Add(&apiregistrationv1.APIService{
					ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
					Spec: apiregistrationv1.APIServiceSpec{
						GroupPriorityMinimum: 111,
						CABundle:             nil,
					},
				})
				hit := false
				c.PrependReactor("update", "apiservices", func(_ kubetesting.Action) (bool, runtime.Object, error) {
					// Return an error on the first call, then fall through to the default (successful) response.
					if !hit {
						// Before the update fails, also change the object that will be returned by the next Get(),
						// to make sure that the production code does a fresh Get() after detecting a conflict.
						_ = c.Tracker().Update(schema.GroupVersionResource{
							Group:    apiregistrationv1.GroupName,
							Version:  apiregistrationv1.SchemeGroupVersion.Version,
							Resource: "apiservices",
						}, &apiregistrationv1.APIService{
							ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
							Spec: apiregistrationv1.APIServiceSpec{
								GroupPriorityMinimum: 222,
								CABundle:             nil,
							},
						}, "")
						hit = true
						return true, nil, apierrors.NewConflict(schema.GroupResource{
							Group:    apiregistrationv1.GroupName,
							Resource: "apiservices",
						}, apiServiceName, fmt.Errorf("there was a conflict"))
					}
					return false, nil, nil
				})
			},
			caInput: []byte("some-ca-bundle"),
			wantObjects: []apiregistrationv1.APIService{{
				ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
				Spec: apiregistrationv1.APIServiceSpec{
					GroupPriorityMinimum: 222,
					CABundle:             []byte("some-ca-bundle"),
				},
			}},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			client := aggregatorv1fake.NewSimpleClientset()
			if tt.mocks != nil {
				tt.mocks(client)
			}

			err := UpdateAPIService(ctx, client, loginv1alpha1.SchemeGroupVersion.Version+"."+loginv1alpha1.GroupName, tt.serviceNamespace, tt.caInput)
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
