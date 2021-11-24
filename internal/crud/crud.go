// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crud

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
)

//nolint:gosec // ignore lint warnings that these are credentials
const (
	SecretLabelKey = "storage.pinniped.dev/type"

	SecretLifetimeAnnotationKey        = "storage.pinniped.dev/garbage-collect-after"
	SecretLifetimeAnnotationDateFormat = time.RFC3339

	secretNameFormat = "pinniped-storage-%s-%s"
	secretTypeFormat = "storage.pinniped.dev/%s"
	secretVersion    = "1"
	secretDataKey    = "pinniped-storage-data"
	secretVersionKey = "pinniped-storage-version"

	ErrSecretTypeMismatch    = constable.Error("secret storage data has incorrect type")
	ErrSecretLabelMismatch   = constable.Error("secret storage data has incorrect label")
	ErrSecretVersionMismatch = constable.Error("secret storage data has incorrect version")
)

type Storage interface {
	Create(ctx context.Context, signature string, data JSON, additionalLabels map[string]string) (resourceVersion string, err error)
	Get(ctx context.Context, signature string, data JSON) (resourceVersion string, err error)
	Update(ctx context.Context, signature, resourceVersion string, data JSON) (newResourceVersion string, err error)
	Delete(ctx context.Context, signature string) error
	DeleteByLabel(ctx context.Context, labelName string, labelValue string) error
}

type JSON interface{} // document that we need valid JSON types

func New(resource string, secrets corev1client.SecretInterface, clock func() time.Time, lifetime time.Duration) Storage {
	return &secretsStorage{
		resource:   resource,
		secretType: secretType(resource),
		secrets:    secrets,
		clock:      clock,
		lifetime:   lifetime,
	}
}

type secretsStorage struct {
	resource   string
	secretType corev1.SecretType
	secrets    corev1client.SecretInterface
	clock      func() time.Time
	lifetime   time.Duration
}

func (s *secretsStorage) Create(ctx context.Context, signature string, data JSON, additionalLabels map[string]string) (string, error) {
	secret, err := s.toSecret(signature, "", data, additionalLabels)
	if err != nil {
		return "", err
	}
	secret, err = s.secrets.Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create %s for signature %s: %w", s.resource, signature, err)
	}
	return secret.ResourceVersion, nil
}

func (s *secretsStorage) Get(ctx context.Context, signature string, data JSON) (string, error) {
	secret, err := s.secrets.Get(ctx, s.getName(signature), metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get %s for signature %s: %w", s.resource, signature, err)
	}

	err = FromSecret(s.resource, secret, data)
	if err != nil {
		return "", fmt.Errorf("error during get for signature %s: %w", signature, err)
	}
	return secret.ResourceVersion, nil
}

func (s *secretsStorage) Update(ctx context.Context, signature, resourceVersion string, data JSON) (string, error) {
	// Note: There may be a small bug here in that toSecret will move the SecretLifetimeAnnotationKey date forward
	// instead of keeping the storage resource's original SecretLifetimeAnnotationKey value. However, we only use
	// this Update method in one place, and it doesn't matter in that place. Be aware that it might need improvement
	// if we start using this Update method in more places.
	secret, err := s.toSecret(signature, resourceVersion, data, nil)
	if err != nil {
		return "", err
	}
	secret, err = s.secrets.Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to update %s for signature %s at resource version %s: %w", s.resource, signature, resourceVersion, err)
	}
	return secret.ResourceVersion, nil
}

func (s *secretsStorage) Delete(ctx context.Context, signature string) error {
	if err := s.secrets.Delete(ctx, s.getName(signature), metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("failed to delete %s for signature %s: %w", s.resource, signature, err)
	}
	return nil
}

func (s *secretsStorage) DeleteByLabel(ctx context.Context, labelName string, labelValue string) error {
	list, err := s.secrets.List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set{
			SecretLabelKey: s.resource,
			labelName:      labelValue,
		}.String(),
	})
	if err != nil {
		return fmt.Errorf(`failed to list secrets for resource "%s" matching label "%s=%s": %w`, s.resource, labelName, labelValue, err)
	}
	if len(list.Items) == 0 {
		return fmt.Errorf(`failed to delete secrets for resource "%s" matching label "%s=%s": none found`, s.resource, labelName, labelValue)
	}
	// TODO try to delete all of the items and consolidate all of the errors and return them all
	for _, secret := range list.Items {
		err = s.secrets.Delete(ctx, secret.Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf(`failed to delete secrets for resource "%s" matching label "%s=%s" with name %s: %w`, s.resource, labelName, labelValue, secret.Name, err)
		}
	}
	return nil
}

// FromSecret is similar to Get, but for when you already have a Secret in hand, e.g. from an informer.
// It validates and unmarshals the Secret. The data parameter is filled in as the result.
func FromSecret(resource string, secret *corev1.Secret, data JSON) error {
	if err := validateSecret(resource, secret); err != nil {
		return err
	}
	if err := json.Unmarshal(secret.Data[secretDataKey], data); err != nil {
		return fmt.Errorf("failed to decode %s: %w", resource, err)
	}
	return nil
}

func secretType(resource string) corev1.SecretType {
	return corev1.SecretType(fmt.Sprintf(secretTypeFormat, resource))
}

func validateSecret(resource string, secret *corev1.Secret) error {
	secretType := corev1.SecretType(fmt.Sprintf(secretTypeFormat, resource))
	if secret.Type != secretType {
		return fmt.Errorf("%w: %s must equal %s", ErrSecretTypeMismatch, secret.Type, secretType)
	}
	if labelResource := secret.Labels[SecretLabelKey]; labelResource != resource {
		return fmt.Errorf("%w: %s must equal %s", ErrSecretLabelMismatch, labelResource, resource)
	}
	if !bytes.Equal(secret.Data[secretVersionKey], []byte(secretVersion)) {
		return ErrSecretVersionMismatch // TODO should this be fatal or not?
	}
	return nil
}

//nolint: gochecknoglobals
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func (s *secretsStorage) getName(signature string) string {
	// try to decode base64 signatures to prevent double encoding of binary data
	signatureBytes := maybeBase64Decode(signature)
	// lower case base32 encoding insures that our secret name is valid per ValidateSecretName in k/k
	signatureAsValidName := strings.ToLower(b32.EncodeToString(signatureBytes))
	return fmt.Sprintf(secretNameFormat, s.resource, signatureAsValidName)
}

func (s *secretsStorage) toSecret(signature, resourceVersion string, data JSON, additionalLabels map[string]string) (*corev1.Secret, error) {
	buf, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode secret data for %s: %w", s.getName(signature), err)
	}

	labelsToAdd := map[string]string{
		SecretLabelKey: s.resource, // make it easier to find this stuff via kubectl
	}
	for labelName, labelValue := range additionalLabels {
		labelsToAdd[labelName] = labelValue
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            s.getName(signature),
			ResourceVersion: resourceVersion,
			Labels:          labelsToAdd,
			Annotations: map[string]string{
				SecretLifetimeAnnotationKey: s.clock().Add(s.lifetime).UTC().Format(SecretLifetimeAnnotationDateFormat),
			},
			OwnerReferences: nil,
		},
		Data: map[string][]byte{
			secretDataKey:    buf,
			secretVersionKey: []byte(secretVersion),
		},
		Type: s.secretType,
	}, nil
}

func maybeBase64Decode(signature string) []byte {
	for _, encoding := range []*base64.Encoding{
		// ordered in most likely used by HMAC, JWT, etc signatures
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if signatureBytes, err := encoding.DecodeString(signature); err == nil {
			return signatureBytes
		}
	}
	return []byte(signature)
}
