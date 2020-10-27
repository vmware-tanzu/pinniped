// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"crypto/tls"
	"sync"
)

type DynamicTLSCertProvider interface {
	SetIssuerHostToTLSCertMap(issuerToJWKSMap map[string]*tls.Certificate)
	SetDefaultTLSCert(certificate *tls.Certificate)
	GetTLSCert(lowercaseIssuerHostName string) *tls.Certificate
	GetDefaultTLSCert() *tls.Certificate
}

type dynamicTLSCertProvider struct {
	issuerHostToTLSCertMap map[string]*tls.Certificate
	defaultCert            *tls.Certificate
	mutex                  sync.RWMutex
}

func NewDynamicTLSCertProvider() DynamicTLSCertProvider {
	return &dynamicTLSCertProvider{
		issuerHostToTLSCertMap: map[string]*tls.Certificate{},
	}
}

func (p *dynamicTLSCertProvider) SetIssuerHostToTLSCertMap(issuerHostToTLSCertMap map[string]*tls.Certificate) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.issuerHostToTLSCertMap = issuerHostToTLSCertMap
}

func (p *dynamicTLSCertProvider) SetDefaultTLSCert(certificate *tls.Certificate) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.defaultCert = certificate
}

func (p *dynamicTLSCertProvider) GetTLSCert(issuerHostName string) *tls.Certificate {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.issuerHostToTLSCertMap[issuerHostName]
}

func (p *dynamicTLSCertProvider) GetDefaultTLSCert() *tls.Certificate {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.defaultCert
}
