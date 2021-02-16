// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuerconfig

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	coretesting "k8s.io/client-go/testing"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
)

func TestCreateOrUpdateCredentialIssuerStatus(t *testing.T) {
	spec.Run(t, "specs", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var ctx context.Context
		var pinnipedAPIClient *pinnipedfake.Clientset
		var credentialIssuerGVR schema.GroupVersionResource
		const credentialIssuerResourceName = "some-resource-name"

		it.Before(func() {
			r = require.New(t)
			ctx = context.Background()
			pinnipedAPIClient = pinnipedfake.NewSimpleClientset()
			credentialIssuerGVR = schema.GroupVersionResource{
				Group:    configv1alpha1.GroupName,
				Version:  configv1alpha1.SchemeGroupVersion.Version,
				Resource: "credentialissuers",
			}
		})

		when("the config does not exist", func() {
			it("creates a new config and then updates it with the func parameter", func() {
				err := CreateOrUpdateCredentialIssuerStatus(
					ctx,
					credentialIssuerResourceName,
					map[string]string{
						"myLabelKey1": "myLabelValue1",
						"myLabelKey2": "myLabelValue2",
					},
					pinnipedAPIClient,
					func(configToUpdate *configv1alpha1.CredentialIssuerStatus) {
						configToUpdate.KubeConfigInfo = &configv1alpha1.CredentialIssuerKubeConfigInfo{
							CertificateAuthorityData: "some-ca-value",
						}
					},
				)
				r.NoError(err)

				expectedGetAction := coretesting.NewRootGetAction(credentialIssuerGVR, credentialIssuerResourceName)

				expectedCreateAction := coretesting.NewRootCreateAction(
					credentialIssuerGVR,
					&configv1alpha1.CredentialIssuer{
						TypeMeta: metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{
							Name: credentialIssuerResourceName,
							Labels: map[string]string{
								"myLabelKey1": "myLabelValue1",
								"myLabelKey2": "myLabelValue2",
							},
						},
					},
				)

				expectedUpdateAction := coretesting.NewRootUpdateSubresourceAction(credentialIssuerGVR, "status",
					&configv1alpha1.CredentialIssuer{
						TypeMeta: metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{
							Name: credentialIssuerResourceName,
							Labels: map[string]string{
								"myLabelKey1": "myLabelValue1",
								"myLabelKey2": "myLabelValue2",
							},
						},
						Status: configv1alpha1.CredentialIssuerStatus{
							KubeConfigInfo: &configv1alpha1.CredentialIssuerKubeConfigInfo{
								Server:                   "",
								CertificateAuthorityData: "some-ca-value",
							},
						},
					},
				)

				r.Equal([]coretesting.Action{expectedGetAction, expectedCreateAction, expectedUpdateAction}, pinnipedAPIClient.Actions())
			})

			when("there is an unexpected error while creating the existing object", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor("create", "credentialissuers", func(_ coretesting.Action) (bool, runtime.Object, error) {
						return true, nil, fmt.Errorf("error on create")
					})
				})

				it("returns an error", func() {
					err := CreateOrUpdateCredentialIssuerStatus(
						ctx,
						credentialIssuerResourceName,
						map[string]string{},
						pinnipedAPIClient,
						func(configToUpdate *configv1alpha1.CredentialIssuerStatus) {},
					)
					r.EqualError(err, "could not create or update credentialissuer: create failed: error on create")
				})
			})
		})

		when("the config already exists", func() {
			var existingConfig *configv1alpha1.CredentialIssuer

			it.Before(func() {
				existingConfig = &configv1alpha1.CredentialIssuer{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: credentialIssuerResourceName,
						Labels: map[string]string{
							"myLabelKey1": "myLabelValue1",
						},
					},
					Status: configv1alpha1.CredentialIssuerStatus{
						Strategies: []configv1alpha1.CredentialIssuerStrategy{
							{
								Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
								Status:         configv1alpha1.SuccessStrategyStatus,
								Reason:         configv1alpha1.FetchedKeyStrategyReason,
								Message:        "initial-message",
								LastUpdateTime: metav1.Now(),
							},
						},
						KubeConfigInfo: &configv1alpha1.CredentialIssuerKubeConfigInfo{
							Server:                   "initial-server-value",
							CertificateAuthorityData: "initial-ca-value",
						},
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(existingConfig))
			})

			it("updates the existing config to only apply the updates made by the func parameter", func() {
				err := CreateOrUpdateCredentialIssuerStatus(
					ctx,
					credentialIssuerResourceName,
					map[string]string{
						"myLabelKey1": "myLabelValue1",
						"myLabelKey2": "myLabelValue2",
					},
					pinnipedAPIClient,
					func(configToUpdate *configv1alpha1.CredentialIssuerStatus) {
						configToUpdate.KubeConfigInfo.CertificateAuthorityData = "new-ca-value"
					},
				)
				r.NoError(err)

				expectedGetAction := coretesting.NewRootGetAction(credentialIssuerGVR, credentialIssuerResourceName)

				// Only the edited field should be changed.
				expectedUpdatedConfig := existingConfig.DeepCopy()
				expectedUpdatedConfig.Status.KubeConfigInfo.CertificateAuthorityData = "new-ca-value"
				expectedUpdateAction := coretesting.NewRootUpdateSubresourceAction(credentialIssuerGVR, "status", expectedUpdatedConfig)

				r.Equal([]coretesting.Action{expectedGetAction, expectedUpdateAction}, pinnipedAPIClient.Actions())
			})

			it("avoids the cost of an update if the local updates made by the func parameter did not actually change anything", func() {
				err := CreateOrUpdateCredentialIssuerStatus(
					ctx,
					credentialIssuerResourceName,
					map[string]string{},
					pinnipedAPIClient,
					func(configToUpdate *configv1alpha1.CredentialIssuerStatus) {
						configToUpdate.KubeConfigInfo.CertificateAuthorityData = "initial-ca-value"

						t := configToUpdate.Strategies[0].LastUpdateTime
						loc, err := time.LoadLocation("Asia/Shanghai")
						r.NoError(err)
						configToUpdate.Strategies[0].LastUpdateTime = metav1.NewTime(t.In(loc))
					},
				)
				r.NoError(err)

				expectedGetAction := coretesting.NewRootGetAction(credentialIssuerGVR, credentialIssuerResourceName)
				r.Equal([]coretesting.Action{expectedGetAction}, pinnipedAPIClient.Actions())
			})

			when("there is an unexpected error while getting the existing object", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor("get", "credentialissuers", func(_ coretesting.Action) (bool, runtime.Object, error) {
						return true, nil, fmt.Errorf("error on get")
					})
				})

				it("returns an error", func() {
					err := CreateOrUpdateCredentialIssuerStatus(
						ctx,
						credentialIssuerResourceName,
						map[string]string{},
						pinnipedAPIClient,
						func(configToUpdate *configv1alpha1.CredentialIssuerStatus) {},
					)
					r.EqualError(err, "could not create or update credentialissuer: get failed: error on get")
				})
			})

			when("there is an unexpected error while updating the existing object", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor("update", "credentialissuers", func(_ coretesting.Action) (bool, runtime.Object, error) {
						return true, nil, fmt.Errorf("error on update")
					})
				})

				it("returns an error", func() {
					err := CreateOrUpdateCredentialIssuerStatus(
						ctx,
						credentialIssuerResourceName,
						map[string]string{},
						pinnipedAPIClient,
						func(configToUpdate *configv1alpha1.CredentialIssuerStatus) {
							configToUpdate.KubeConfigInfo.CertificateAuthorityData = "new-ca-value"
						},
					)
					r.EqualError(err, "could not create or update credentialissuer: error on update")
				})
			})

			when("there is a conflict error while updating the existing object on the first try and the next try succeeds", func() {
				var slightlyDifferentExistingConfig *configv1alpha1.CredentialIssuer

				it.Before(func() {
					hit := false
					slightlyDifferentExistingConfig = existingConfig.DeepCopy()
					slightlyDifferentExistingConfig.Status.KubeConfigInfo.Server = "some-other-server-value-from-conflicting-update"

					pinnipedAPIClient.PrependReactor("update", "credentialissuers", func(_ coretesting.Action) (bool, runtime.Object, error) {
						// Return an error on the first call, then fall through to the default (successful) response.
						if !hit {
							// Before the update fails, also change the object that will be returned by the next Get(),
							// to make sure that the production code does a fresh Get() after detecting a conflict.
							r.NoError(pinnipedAPIClient.Tracker().Update(credentialIssuerGVR, slightlyDifferentExistingConfig, ""))
							hit = true
							return true, nil, apierrors.NewConflict(schema.GroupResource{
								Group:    apiregistrationv1.GroupName,
								Resource: "credentialissuers",
							}, "alphav1.pinniped.dev", fmt.Errorf("there was a conflict"))
						}
						return false, nil, nil
					})
				})

				it("retries updates on conflict", func() {
					err := CreateOrUpdateCredentialIssuerStatus(
						ctx,
						credentialIssuerResourceName,
						map[string]string{
							"myLabelKey1": "myLabelValue1",
							"myLabelKey2": "myLabelValue2",
						},
						pinnipedAPIClient,
						func(configToUpdate *configv1alpha1.CredentialIssuerStatus) {
							configToUpdate.KubeConfigInfo.CertificateAuthorityData = "new-ca-value"
						},
					)
					r.NoError(err)

					expectedGetAction := coretesting.NewRootGetAction(credentialIssuerGVR, credentialIssuerResourceName)

					// The first attempted update only includes its own edits.
					firstExpectedUpdatedConfig := existingConfig.DeepCopy()
					firstExpectedUpdatedConfig.Status.KubeConfigInfo.CertificateAuthorityData = "new-ca-value"
					firstExpectedUpdateAction := coretesting.NewRootUpdateSubresourceAction(credentialIssuerGVR, "status", firstExpectedUpdatedConfig)

					// Both the edits made by this update and the edits made by the conflicting update should be included.
					secondExpectedUpdatedConfig := existingConfig.DeepCopy()
					secondExpectedUpdatedConfig.Status.KubeConfigInfo.Server = "some-other-server-value-from-conflicting-update"
					secondExpectedUpdatedConfig.Status.KubeConfigInfo.CertificateAuthorityData = "new-ca-value"
					secondExpectedUpdateAction := coretesting.NewRootUpdateSubresourceAction(credentialIssuerGVR, "status", secondExpectedUpdatedConfig)

					expectedActions := []coretesting.Action{
						expectedGetAction,
						firstExpectedUpdateAction,
						expectedGetAction,
						secondExpectedUpdateAction,
					}
					r.Equal(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
