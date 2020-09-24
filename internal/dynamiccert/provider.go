// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dynamiccert

import (
	"sync"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"
)

// Provider provides a getter, CurrentCertKeyContent(), and a setter, Set(), for a PEM-formatted
// certificate and matching key.
type Provider interface {
	dynamiccertificates.CertKeyContentProvider
	Set(certPEM, keyPEM []byte)
}

type provider struct {
	certPEM []byte
	keyPEM  []byte
	mutex   sync.RWMutex
}

// New returns an empty Provider. The returned Provider is thread-safe.
func New() Provider {
	return &provider{}
}

func (p *provider) Set(certPEM, keyPEM []byte) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.certPEM = certPEM
	p.keyPEM = keyPEM
}

func (p *provider) Name() string {
	return "DynamicCertProvider"
}

func (p *provider) CurrentCertKeyContent() (cert []byte, key []byte) {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.certPEM, p.keyPEM
}
