// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crud

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ory/fosite/compose"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
)

func TestStorage(t *testing.T) {
	ctx := context.Background()
	secretsGVR := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "secrets",
	}

	type testJSON struct {
		Data string
	}

	type mocker interface {
		AddReactor(verb, resource string, reaction coretesting.ReactionFunc)
		PrependReactor(verb, resource string, reaction coretesting.ReactionFunc)
		Tracker() coretesting.ObjectTracker
	}

	hmac := compose.NewOAuth2HMACStrategy(&compose.Config{}, []byte("super-secret-32-byte-for-testing"), nil)
	// test data generation via:
	// code, signature, err := hmac.GenerateAuthorizeCode(ctx, nil)

	validateSecretName := validation.NameIsDNSSubdomain // matches k/k

	const (
		namespace          = "test-ns"
		authorizationCode1 = "81qE408EKL-e99gcXo3UnXBz9W05yGm92_hBmvXeadM.R5h38Bmw7yOaWNy0ypB3feh9toM-3T2zlwMXQyeE9B0"
		authorizationCode2 = "p7aIiOLy-btBBlCro5RWm1QABANKCiC0JmDPhUtfOY4.XXJsYsMWhnSMJi9TXJcPO6SDVO2R_QXImwroxxnQPA8"
		authorizationCode3 = "skKp1RjGgIwZhT3vaB_k1F3cIj2yp7U8a7UD0xAaemU.5aUhdNmfWLW3yKX8Zfz5ztS5IiiWBgu36Gja-o2xl0I"
	)

	tests := []struct {
		name        string
		resource    string
		mocks       func(*testing.T, mocker)
		run         func(*testing.T, Storage) error
		wantActions []coretesting.Action
		wantSecrets []corev1.Secret
		wantErr     string
	}{
		{
			name:     "get non-existent",
			resource: "authcode",
			mocks:    nil,
			run: func(t *testing.T, storage Storage) error {
				_, err := storage.Get(ctx, "not-exists", nil)
				return err
			},
			wantActions: []coretesting.Action{
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-authcode-t2fx46yyvs3a"),
			},
			wantSecrets: nil,
			wantErr:     `failed to get authcode for signature not-exists: secrets "pinniped-storage-authcode-t2fx46yyvs3a" not found`,
		},
		{
			name:     "delete non-existent",
			resource: "tokens",
			mocks:    nil,
			run: func(t *testing.T, storage Storage) error {
				return storage.Delete(ctx, "not-a-token")
			},
			wantActions: []coretesting.Action{
				coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-tokens-t2fx427lnci6s"),
			},
			wantSecrets: nil,
			wantErr:     `failed to delete tokens for signature not-a-token: secrets "pinniped-storage-tokens-t2fx427lnci6s" not found`,
		},
		// TODO make a delete non-existent test for DeleteByLabel
		{
			name:     "create and get",
			resource: "access-tokens",
			mocks:    nil,
			run: func(t *testing.T, storage Storage) error {
				signature := hmac.AuthorizeCodeSignature(authorizationCode1)
				require.NotEmpty(t, signature)
				require.NotEmpty(t, validateSecretName(signature, false)) // signature is not valid secret name as-is

				data := &testJSON{Data: "create-and-get"}
				rv1, err := storage.Create(ctx, signature, data, nil)
				require.Empty(t, rv1) // fake client does not set this
				require.NoError(t, err)

				out := &testJSON{}
				rv2, err := storage.Get(ctx, signature, out)
				require.Empty(t, rv2) // fake client does not set this
				require.NoError(t, err)
				require.Equal(t, data, out)

				return nil
			},
			wantActions: []coretesting.Action{
				coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-access-tokens-i6mhp4azwdxshgsy3s2mvedxpxuh3nudh3ot3m4xamlugj4e6qoq",
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "access-tokens",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"create-and-get"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/access-tokens",
				}),
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-access-tokens-i6mhp4azwdxshgsy3s2mvedxpxuh3nudh3ot3m4xamlugj4e6qoq"),
			},
			wantSecrets: []corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-access-tokens-i6mhp4azwdxshgsy3s2mvedxpxuh3nudh3ot3m4xamlugj4e6qoq",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "access-tokens",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"create-and-get"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/access-tokens",
				},
			},
			wantErr: "",
		},
		{
			name:     "create and get with additional labels",
			resource: "access-tokens",
			mocks:    nil,
			run: func(t *testing.T, storage Storage) error {
				signature := hmac.AuthorizeCodeSignature(authorizationCode1)
				require.NotEmpty(t, signature)
				require.NotEmpty(t, validateSecretName(signature, false)) // signature is not valid secret name as-is

				data := &testJSON{Data: "create-and-get"}
				rv1, err := storage.Create(ctx, signature, data, map[string]string{"label1": "value1", "label2": "value2"})
				require.Empty(t, rv1) // fake client does not set this
				require.NoError(t, err)

				out := &testJSON{}
				rv2, err := storage.Get(ctx, signature, out)
				require.Empty(t, rv2) // fake client does not set this
				require.NoError(t, err)
				require.Equal(t, data, out)

				return nil
			},
			wantActions: []coretesting.Action{
				coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-access-tokens-i6mhp4azwdxshgsy3s2mvedxpxuh3nudh3ot3m4xamlugj4e6qoq",
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "access-tokens",
							"label1":                    "value1",
							"label2":                    "value2",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"create-and-get"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/access-tokens",
				}),
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-access-tokens-i6mhp4azwdxshgsy3s2mvedxpxuh3nudh3ot3m4xamlugj4e6qoq"),
			},
			wantSecrets: []corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-access-tokens-i6mhp4azwdxshgsy3s2mvedxpxuh3nudh3ot3m4xamlugj4e6qoq",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "access-tokens",
							"label1":                    "value1",
							"label2":                    "value2",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"create-and-get"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/access-tokens",
				},
			},
			wantErr: "",
		},
		{
			name:     "get existing",
			resource: "pandas-are-best",
			mocks: func(t *testing.T, mock mocker) {
				err := mock.Tracker().Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-pandas-are-best-lvzgyywdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "pandas-are-best",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"snorlax"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/pandas-are-best",
				})
				require.NoError(t, err)
			},
			run: func(t *testing.T, storage Storage) error {
				signature := hmac.AuthorizeCodeSignature(authorizationCode2)
				require.NotEmpty(t, signature)
				require.NotEmpty(t, validateSecretName(signature, false)) // signature is not valid secret name as-is

				data := &testJSON{Data: "snorlax"}
				out := &testJSON{}
				rv1, err := storage.Get(ctx, signature, out)
				require.Empty(t, rv1) // fake client does not set this
				require.NoError(t, err)
				require.Equal(t, data, out)

				return nil
			},
			wantActions: []coretesting.Action{
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-pandas-are-best-lvzgyywdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq"),
			},
			wantSecrets: []corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-pandas-are-best-lvzgyywdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "pandas-are-best",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"snorlax"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/pandas-are-best",
				},
			},
			wantErr: "",
		},
		{
			name:     "update existing",
			resource: "stores",
			mocks: func(t *testing.T, mock mocker) {
				err := mock.Tracker().Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-stores-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba",
						Namespace:       namespace,
						ResourceVersion: "35",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "stores",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"pants"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/stores",
				})
				require.NoError(t, err)

				mock.PrependReactor("update", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					secret := action.(coretesting.UpdateAction).GetObject().(*corev1.Secret)
					secret.ResourceVersion = "45"
					return false, nil, nil // we mutated the secret in place but we do not "handle" it
				})
			},
			run: func(t *testing.T, storage Storage) error {
				signature := hmac.AuthorizeCodeSignature(authorizationCode3)
				require.NotEmpty(t, signature)
				require.NotEmpty(t, validateSecretName(signature, false)) // signature is not valid secret name as-is

				data := &testJSON{Data: "pants"}
				out := &testJSON{}
				rv1, err := storage.Get(ctx, signature, out)
				require.Equal(t, "35", rv1) // set in mock above
				require.NoError(t, err)
				require.Equal(t, data, out)

				newData := &testJSON{Data: "shirts"}
				rv2, err := storage.Update(ctx, signature, rv1, newData)
				require.Equal(t, "45", rv2) // mock sets to a higher value on update
				require.NoError(t, err)

				newOut := &testJSON{}
				rv3, err := storage.Get(ctx, signature, newOut)
				require.Equal(t, "45", rv3) // we should see new rv now
				require.NoError(t, err)
				require.Equal(t, newData, newOut)

				return nil
			},
			wantActions: []coretesting.Action{
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-stores-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba"),
				coretesting.NewUpdateAction(secretsGVR, namespace, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-stores-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba",
						ResourceVersion: "35", // update at initial RV
						Labels: map[string]string{
							"storage.pinniped.dev/type": "stores",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"shirts"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/stores",
				}),
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-stores-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba"),
			},
			wantSecrets: []corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-stores-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba",
						Namespace:       namespace,
						ResourceVersion: "45", // final list at new RV
						Labels: map[string]string{
							"storage.pinniped.dev/type": "stores",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"shirts"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/stores",
				},
			},
			wantErr: "",
		},
		{
			name:     "delete existing",
			resource: "seals",
			mocks: func(t *testing.T, mock mocker) {
				err := mock.Tracker().Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-seals-lvzgyywdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "seals",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"sad-seal"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/seals",
				})
				require.NoError(t, err)
			},
			run: func(t *testing.T, storage Storage) error {
				signature := hmac.AuthorizeCodeSignature(authorizationCode2)
				require.NotEmpty(t, signature)
				require.NotEmpty(t, validateSecretName(signature, false)) // signature is not valid secret name as-is

				return storage.Delete(ctx, signature)
			},
			wantActions: []coretesting.Action{
				coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-seals-lvzgyywdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq"),
			},
			wantSecrets: nil,
			wantErr:     "",
		},
		{
			name:     "delete existing by label",
			resource: "seals",
			mocks: func(t *testing.T, mock mocker) {
				require.NoError(t, mock.Tracker().Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-seals-lvzgyywdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "seals",
							"additionalLabel":           "matching-value",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"sad-seal"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/seals",
				}))
				require.NoError(t, mock.Tracker().Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-seals-abcdywdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "seals",
							"additionalLabel":           "matching-value",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"happy-seal"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/seals",
				}))
				require.NoError(t, mock.Tracker().Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-seals-12345wdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "seals",              // same type as above
							"additionalLabel":           "non-matching-value", // different value for the same label
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"sad-seal2"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/seals",
				}))
				require.NoError(t, mock.Tracker().Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-seals-54321wdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "walruses",       // different type from above
							"additionalLabel":           "matching-value", // same value for the same label as above
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"sad-seal3"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/walruses",
				}))
			},
			run: func(t *testing.T, storage Storage) error {
				return storage.DeleteByLabel(ctx, "additionalLabel", "matching-value")
			},
			wantActions: []coretesting.Action{
				coretesting.NewListAction(secretsGVR, schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}, namespace, metav1.ListOptions{
					LabelSelector: "storage.pinniped.dev/type=seals,additionalLabel=matching-value",
				}),
				coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-seals-abcdywdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq"),
				coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-seals-lvzgyywdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq"),
			},
			wantSecrets: []corev1.Secret{
				// the secret of the same type whose label did not match is not deleted
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-seals-12345wdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "seals",              // same type as above
							"additionalLabel":           "non-matching-value", // different value for the same label
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"sad-seal2"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/seals",
				},
				// the secrets of other types are not deleted, even if they have a matching label
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-seals-54321wdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "walruses",       // different type from above
							"additionalLabel":           "matching-value", // same value for the same label as above
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"sad-seal3"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/walruses",
				},
			},
			wantErr: "",
		},
		{
			name:     "when there is an error performing the delete while deleting by label",
			resource: "seals",
			mocks: func(t *testing.T, mock mocker) {
				require.NoError(t, mock.Tracker().Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-seals-lvzgyywdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "seals",
							"additionalLabel":           "matching-value",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"sad-seal"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/seals",
				}))
				mock.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("some delete error")
				})
			},
			run: func(t *testing.T, storage Storage) error {
				return storage.DeleteByLabel(ctx, "additionalLabel", "matching-value")
			},
			wantActions: []coretesting.Action{
				coretesting.NewListAction(secretsGVR, schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}, namespace, metav1.ListOptions{
					LabelSelector: "storage.pinniped.dev/type=seals,additionalLabel=matching-value",
				}),
				coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-seals-lvzgyywdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq"),
			},
			wantSecrets: []corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-seals-lvzgyywdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "seals",
							"additionalLabel":           "matching-value",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"sad-seal"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/seals",
				},
			},
			wantErr: `failed to delete secrets for resource "seals" matching label "additionalLabel=matching-value" with name pinniped-storage-seals-lvzgyywdc2dhjdbgf5jvzfyphosigvhnsh6qlse3blumogoqhqhq: some delete error`,
		},
		{
			name:     "when there is an error listing secrets during a delete by label operation",
			resource: "seals",
			mocks: func(t *testing.T, mock mocker) {
				mock.PrependReactor("list", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					listAction := action.(coretesting.ListActionImpl)
					labelRestrictions := listAction.GetListRestrictions().Labels
					requiresExactMatch, found := labelRestrictions.RequiresExactMatch("additionalLabel")
					if !found || requiresExactMatch != "matching-value" {
						// this list action did not use label selector additionalLabel=matching-value, so allow it to proceed without intervention
						return false, nil, nil
					}
					requiresExactMatch, found = labelRestrictions.RequiresExactMatch("storage.pinniped.dev/type")
					if !found || requiresExactMatch != "seals" {
						// this list action did not use label selector storage.pinniped.dev/type=seals, so allow it to proceed without intervention
						return false, nil, nil
					}
					// this list action was the one that did use the expected label selectors so cause it to error
					return true, nil, fmt.Errorf("some listing error")
				})
			},
			run: func(t *testing.T, storage Storage) error {
				return storage.DeleteByLabel(ctx, "additionalLabel", "matching-value")
			},
			wantActions: []coretesting.Action{
				coretesting.NewListAction(secretsGVR, schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}, namespace, metav1.ListOptions{
					LabelSelector: "storage.pinniped.dev/type=seals,additionalLabel=matching-value",
				}),
			},
			wantErr: `failed to list secrets for resource "seals" matching label "additionalLabel=matching-value": some listing error`,
		},
		{
			name:     "invalid exiting secret type",
			resource: "candies",
			mocks: func(t *testing.T, mock mocker) {
				err := mock.Tracker().Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-candies-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba",
						Namespace:       namespace,
						ResourceVersion: "55",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "candies",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"twizzlers"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/candies-not",
				})
				require.NoError(t, err)
			},
			run: func(t *testing.T, storage Storage) error {
				signature := hmac.AuthorizeCodeSignature(authorizationCode3)
				require.NotEmpty(t, signature)
				require.NotEmpty(t, validateSecretName(signature, false)) // signature is not valid secret name as-is

				out := &testJSON{}
				rv1, err := storage.Get(ctx, signature, out)
				require.Empty(t, rv1)
				require.Empty(t, out.Data)
				require.True(t, errors.Is(err, ErrSecretTypeMismatch))
				require.EqualError(t, err, "secret storage data has incorrect type: storage.pinniped.dev/candies-not must equal storage.pinniped.dev/candies")

				return nil
			},
			wantActions: []coretesting.Action{
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-candies-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba"),
			},
			wantSecrets: []corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-candies-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba",
						Namespace:       namespace,
						ResourceVersion: "55",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "candies",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"twizzlers"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/candies-not",
				},
			},
			wantErr: "",
		},
		{
			name:     "invalid exiting secret wrong label",
			resource: "candies",
			mocks: func(t *testing.T, mock mocker) {
				err := mock.Tracker().Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-candies-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba",
						Namespace:       namespace,
						ResourceVersion: "55",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "candies-are-bad",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"twizzlers"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/candies",
				})
				require.NoError(t, err)
			},
			run: func(t *testing.T, storage Storage) error {
				signature := hmac.AuthorizeCodeSignature(authorizationCode3)
				require.NotEmpty(t, signature)
				require.NotEmpty(t, validateSecretName(signature, false)) // signature is not valid secret name as-is

				out := &testJSON{}
				rv1, err := storage.Get(ctx, signature, out)
				require.Empty(t, rv1)
				require.Empty(t, out.Data)
				require.True(t, errors.Is(err, ErrSecretLabelMismatch))
				require.EqualError(t, err, "secret storage data has incorrect label: candies-are-bad must equal candies")

				return nil
			},
			wantActions: []coretesting.Action{
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-candies-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba"),
			},
			wantSecrets: []corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-candies-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba",
						Namespace:       namespace,
						ResourceVersion: "55",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "candies-are-bad",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"twizzlers"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/candies",
				},
			},
			wantErr: "",
		},
		{
			name:     "invalid exiting secret wrong version",
			resource: "candies",
			mocks: func(t *testing.T, mock mocker) {
				err := mock.Tracker().Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-candies-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba",
						Namespace:       namespace,
						ResourceVersion: "55",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "candies",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"twizzlers"}`),
						"pinniped-storage-version": []byte("77"),
					},
					Type: "storage.pinniped.dev/candies",
				})
				require.NoError(t, err)
			},
			run: func(t *testing.T, storage Storage) error {
				signature := hmac.AuthorizeCodeSignature(authorizationCode3)
				require.NotEmpty(t, signature)
				require.NotEmpty(t, validateSecretName(signature, false)) // signature is not valid secret name as-is

				out := &testJSON{}
				rv1, err := storage.Get(ctx, signature, out)
				require.Empty(t, rv1)
				require.Empty(t, out.Data)
				require.True(t, errors.Is(err, ErrSecretVersionMismatch))
				require.EqualError(t, err, "secret storage data has incorrect version")

				return nil
			},
			wantActions: []coretesting.Action{
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-candies-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba"),
			},
			wantSecrets: []corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-candies-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba",
						Namespace:       namespace,
						ResourceVersion: "55",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "candies",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"Data":"twizzlers"}`),
						"pinniped-storage-version": []byte("77"),
					},
					Type: "storage.pinniped.dev/candies",
				},
			},
			wantErr: "",
		},
		{
			name:     "invalid exiting secret not json",
			resource: "candies",
			mocks: func(t *testing.T, mock mocker) {
				err := mock.Tracker().Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-candies-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba",
						Namespace:       namespace,
						ResourceVersion: "55",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "candies",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`}}bad data{{`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/candies",
				})
				require.NoError(t, err)
			},
			run: func(t *testing.T, storage Storage) error {
				signature := hmac.AuthorizeCodeSignature(authorizationCode3)
				require.NotEmpty(t, signature)
				require.NotEmpty(t, validateSecretName(signature, false)) // signature is not valid secret name as-is

				out := &testJSON{}
				rv1, err := storage.Get(ctx, signature, out)
				require.Empty(t, rv1)
				require.Empty(t, out.Data)
				require.EqualError(t, err, "failed to decode candies for signature 5aUhdNmfWLW3yKX8Zfz5ztS5IiiWBgu36Gja-o2xl0I: invalid character '}' looking for beginning of value")

				return nil
			},
			wantActions: []coretesting.Action{
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-candies-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba"),
			},
			wantSecrets: []corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-candies-4wssc5gzt5mlln6iux6gl7hzz3klsirisydaxn7indnpvdnrs5ba",
						Namespace:       namespace,
						ResourceVersion: "55",
						Labels: map[string]string{
							"storage.pinniped.dev/type": "candies",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`}}bad data{{`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/candies",
				},
			},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := fake.NewSimpleClientset()
			if tt.mocks != nil {
				tt.mocks(t, client)
			}
			secrets := client.CoreV1().Secrets(namespace)
			storage := New(tt.resource, secrets)

			err := tt.run(t, storage)

			require.Equal(t, tt.wantErr, errString(err))
			require.Equal(t, tt.wantActions, client.Actions())
			checkSecretActionNames(t, client.Actions())
			actualSecrets, err := secrets.List(ctx, metav1.ListOptions{})
			require.NoError(t, err)
			require.Equal(t, tt.wantSecrets, actualSecrets.Items)
			checkSecretListNames(t, actualSecrets.Items)
		})
	}
}

func checkSecretActionNames(t *testing.T, actions []coretesting.Action) {
	t.Helper()

	for _, action := range actions {
		_, ok := action.(coretesting.ListActionImpl)
		if !ok { // list action don't have names, so skip these assertions for list actions
			name := getName(t, action)
			assertValidName(t, name)
		}
	}
}

func checkSecretListNames(t *testing.T, secrets []corev1.Secret) {
	t.Helper()

	for _, secret := range secrets {
		assertValidName(t, secret.Name)
	}
}

func assertValidName(t *testing.T, name string) {
	t.Helper()

	validateSecretName := validation.NameIsDNSSubdomain // matches k/k

	require.NotEmpty(t, name)
	require.Empty(t, validateSecretName(name, false))
	require.Empty(t, validateSecretName(name, true)) // I do not think we actually care about this case
}

func getName(t *testing.T, action coretesting.Action) string {
	t.Helper()

	if getter, ok := action.(interface {
		GetName() string
	}); ok {
		return getter.GetName()
	}

	if getter, ok := action.(interface {
		GetObject() runtime.Object
	}); ok {
		accessor, err := meta.Accessor(getter.GetObject())
		require.NoError(t, err)
		return accessor.GetName()
	}

	t.Fatalf("failed to get name for action: %#v", action)
	panic("unreachable")
}

func errString(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
