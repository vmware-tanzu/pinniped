/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"sync"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"
)

type DynamicTLSServingCertProvider interface {
	dynamiccertificates.CertKeyContentProvider
	Set(certPEM, keyPEM []byte)
}

type dynamicTLSServingCertProvider struct {
	certPEM []byte
	keyPEM  []byte
	mutex   sync.RWMutex
}

func NewDynamicTLSServingCertProvider() DynamicTLSServingCertProvider {
	return &dynamicTLSServingCertProvider{}
}

func (p *dynamicTLSServingCertProvider) Set(certPEM, keyPEM []byte) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.certPEM = certPEM
	p.keyPEM = keyPEM
}

func (p *dynamicTLSServingCertProvider) Name() string {
	return "DynamicTLSServingCertProvider"
}

func (p *dynamicTLSServingCertProvider) CurrentCertKeyContent() (cert []byte, key []byte) {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.certPEM, p.keyPEM
}
