// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package jwks

import (
	"sync"

	"gopkg.in/square/go-jose.v2"
)

type DynamicJWKSProvider interface {
	SetIssuerToJWKSMap(issuerToJWKSMap map[string]*jose.JSONWebKeySet)
	GetJWKS(issuerName string) *jose.JSONWebKeySet
}

type dynamicJWKSProvider struct {
	issuerToJWKSMap map[string]*jose.JSONWebKeySet
	mutex           sync.RWMutex
}

func NewDynamicJWKSProvider() DynamicJWKSProvider {
	return &dynamicJWKSProvider{
		issuerToJWKSMap: map[string]*jose.JSONWebKeySet{},
	}
}

func (p *dynamicJWKSProvider) SetIssuerToJWKSMap(issuerToJWKSMap map[string]*jose.JSONWebKeySet) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.issuerToJWKSMap = issuerToJWKSMap
}

func (p *dynamicJWKSProvider) GetJWKS(issuerName string) *jose.JSONWebKeySet {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.issuerToJWKSMap[issuerName]
}
