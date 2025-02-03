// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"hash"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

// DynamicGlobalSecretConfig is a wrapper around fosite.Config which allows us to always return dynamic secrets,
// since those secrets can change at any time when they are loaded or reloaded by our controllers.
type DynamicGlobalSecretConfig struct {
	fositeConfig *fosite.Config
	keyFunc      func() []byte
}

var _ compose.HMACSHAStrategyConfigurator = &DynamicGlobalSecretConfig{}

func NewDynamicGlobalSecretConfig(
	fositeConfig *fosite.Config,
	keyFunc func() []byte,
) *DynamicGlobalSecretConfig {
	return &DynamicGlobalSecretConfig{
		fositeConfig: fositeConfig,
		keyFunc:      keyFunc,
	}
}

func (d *DynamicGlobalSecretConfig) GetAccessTokenLifespan(ctx context.Context) time.Duration {
	return d.fositeConfig.GetAccessTokenLifespan(ctx)
}

func (d *DynamicGlobalSecretConfig) GetRefreshTokenLifespan(ctx context.Context) time.Duration {
	return d.fositeConfig.GetRefreshTokenLifespan(ctx)
}

func (d *DynamicGlobalSecretConfig) GetAuthorizeCodeLifespan(ctx context.Context) time.Duration {
	return d.fositeConfig.GetAuthorizeCodeLifespan(ctx)
}

func (d *DynamicGlobalSecretConfig) GetTokenEntropy(ctx context.Context) int {
	return d.fositeConfig.GetTokenEntropy(ctx)
}

func (d *DynamicGlobalSecretConfig) GetHMACHasher(ctx context.Context) func() hash.Hash {
	return d.fositeConfig.GetHMACHasher(ctx)
}

func (d *DynamicGlobalSecretConfig) GetGlobalSecret(_ctx context.Context) ([]byte, error) {
	// Always call keyFunc() without ever caching its value, because that is the whole point
	// of this type. We want the global secret to be dynamic.
	return d.keyFunc(), nil
}

func (d *DynamicGlobalSecretConfig) GetRotatedGlobalSecrets(_ctx context.Context) ([][]byte, error) {
	// We don't support having multiple global secrets yet, but when we do we will need to implement this.
	return nil, nil
}

func (d *DynamicGlobalSecretConfig) GetDeviceAndUserCodeLifespan(_ctx context.Context) time.Duration {
	return d.fositeConfig.DeviceAndUserCodeLifespan
}
