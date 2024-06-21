// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package jwks

import (
	"sync"

	"github.com/go-jose/go-jose/v4"
)

type DynamicJWKSProvider interface {
	SetIssuerToJWKSMap(
		issuerToJWKSMap map[string]*jose.JSONWebKeySet,
		issuerToActiveJWKMap map[string]*jose.JSONWebKey,
	)
	GetJWKS(issuerName string) (jwks *jose.JSONWebKeySet, activeJWK *jose.JSONWebKey)
}

type dynamicJWKSProvider struct {
	issuerToJWKSMap      map[string]*jose.JSONWebKeySet
	issuerToActiveJWKMap map[string]*jose.JSONWebKey
	mutex                sync.RWMutex
}

func NewDynamicJWKSProvider() DynamicJWKSProvider {
	return &dynamicJWKSProvider{
		issuerToJWKSMap:      map[string]*jose.JSONWebKeySet{},
		issuerToActiveJWKMap: map[string]*jose.JSONWebKey{},
	}
}

func (p *dynamicJWKSProvider) SetIssuerToJWKSMap(
	issuerToJWKSMap map[string]*jose.JSONWebKeySet,
	issuerToActiveJWKMap map[string]*jose.JSONWebKey,
) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.issuerToJWKSMap = issuerToJWKSMap
	p.issuerToActiveJWKMap = issuerToActiveJWKMap
}

func (p *dynamicJWKSProvider) GetJWKS(issuerName string) (*jose.JSONWebKeySet, *jose.JSONWebKey) {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.issuerToJWKSMap[issuerName], p.issuerToActiveJWKMap[issuerName]
}
