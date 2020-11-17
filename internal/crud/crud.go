// Copyright 2020 the Pinniped contributors. All Rights Reserved.
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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
)

//nolint:gosec // ignore lint warnings that these are credentials
const (
	secretNameFormat = "pinniped-storage-%s-%s"
	secretLabelKey   = "storage.pinniped.dev"
	secretTypeFormat = "storage.pinniped.dev/%s"
	secretVersion    = "1"
	secretDataKey    = "pinniped-storage-data"
	secretVersionKey = "pinniped-storage-version"

	ErrSecretTypeMismatch    = constable.Error("secret storage data has incorrect type")
	ErrSecretLabelMismatch   = constable.Error("secret storage data has incorrect label")
	ErrSecretVersionMismatch = constable.Error("secret storage data has incorrect version") // TODO do we need this?
)

type Storage interface {
	Create(ctx context.Context, signature string, data JSON) (resourceVersion string, err error)
	Get(ctx context.Context, signature string, data JSON) (resourceVersion string, err error)
	Update(ctx context.Context, signature, resourceVersion string, data JSON) (newResourceVersion string, err error)
	Delete(ctx context.Context, signature string) error
}

type JSON interface{} // document that we need valid JSON types

func New(resource string, secrets corev1client.SecretInterface) Storage {
	return &secretsStorage{
		resource:      resource,
		secretType:    corev1.SecretType(fmt.Sprintf(secretTypeFormat, resource)),
		secretVersion: []byte(secretVersion),
		secrets:       secrets,
	}
}

type secretsStorage struct {
	resource      string
	secretType    corev1.SecretType
	secretVersion []byte
	secrets       corev1client.SecretInterface
}

func (s *secretsStorage) Create(ctx context.Context, signature string, data JSON) (string, error) {
	secret, err := s.toSecret(signature, "", data)
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
	if err := s.validateSecret(secret); err != nil {
		return "", err
	}
	if err := json.Unmarshal(secret.Data[secretDataKey], data); err != nil {
		return "", fmt.Errorf("failed to decode %s for signature %s: %w", s.resource, signature, err)
	}
	return secret.ResourceVersion, nil
}

func (s *secretsStorage) validateSecret(secret *corev1.Secret) error {
	if secret.Type != s.secretType {
		return fmt.Errorf("%w: %s must equal %s", ErrSecretTypeMismatch, secret.Type, s.secretType)
	}
	if labelResource := secret.Labels[secretLabelKey]; labelResource != s.resource {
		return fmt.Errorf("%w: %s must equal %s", ErrSecretLabelMismatch, labelResource, s.resource)
	}
	if !bytes.Equal(secret.Data[secretVersionKey], s.secretVersion) {
		return ErrSecretVersionMismatch // TODO should this be fatal or not?
	}
	return nil
}

func (s *secretsStorage) Update(ctx context.Context, signature, resourceVersion string, data JSON) (string, error) {
	secret, err := s.toSecret(signature, resourceVersion, data)
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

//nolint: gochecknoglobals
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func (s *secretsStorage) getName(signature string) string {
	// try to decode base64 signatures to prevent double encoding of binary data
	signatureBytes := maybeBase64Decode(signature)
	// lower case base32 encoding insures that our secret name is valid per ValidateSecretName in k/k
	signatureAsValidName := strings.ToLower(b32.EncodeToString(signatureBytes))
	return fmt.Sprintf(secretNameFormat, s.resource, signatureAsValidName)
}

func (s *secretsStorage) toSecret(signature, resourceVersion string, data JSON) (*corev1.Secret, error) {
	buf, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode secret data for %s: %w", s.getName(signature), err)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            s.getName(signature),
			ResourceVersion: resourceVersion,
			Labels: map[string]string{
				secretLabelKey: s.resource, // make it easier to find this stuff via kubectl
			},
			OwnerReferences: nil, // TODO we should set this to make sure stuff gets clean up
		},
		Data: map[string][]byte{
			secretDataKey:    buf,
			secretVersionKey: s.secretVersion,
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
