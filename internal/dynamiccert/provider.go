// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dynamiccert

import (
	"crypto/x509"
	"sync"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"
)

// Provider provides a getter, CurrentCertKeyContent(), and a setter, Set(), for a PEM-formatted
// certificate and matching key.
type Provider interface {
	dynamiccertificates.CertKeyContentProvider
	// TODO dynamiccertificates.Notifier
	// TODO dynamiccertificates.ControllerRunner ???
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

func NewCAProvider(delegate dynamiccertificates.CertKeyContentProvider) dynamiccertificates.CAContentProvider {
	return &caContentProvider{delegate: delegate}
}

type caContentProvider struct {
	delegate dynamiccertificates.CertKeyContentProvider
}

func (c *caContentProvider) Name() string {
	return "DynamicCAProvider"
}

func (c *caContentProvider) CurrentCABundleContent() []byte {
	ca, _ := c.delegate.CurrentCertKeyContent()
	return ca
}

func (c *caContentProvider) VerifyOptions() (x509.VerifyOptions, bool) {
	return x509.VerifyOptions{}, false // assume we are unioned via dynamiccertificates.NewUnionCAContentProvider
}

// TODO look at both the serving side union struct and the ca side union struct for all optional interfaces
//  and then implement everything that makes sense for us to implement
