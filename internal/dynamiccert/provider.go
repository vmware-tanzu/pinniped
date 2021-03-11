// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dynamiccert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"
)

type Provider interface {
	Private
	Public
}

type Private interface {
	dynamiccertificates.CertKeyContentProvider
	SetCertKeyContent(certPEM, keyPEM []byte) error
	UnsetCertKeyContent()

	notifier
}

type Public interface {
	dynamiccertificates.CAContentProvider

	notifier
}

type notifier interface {
	dynamiccertificates.Notifier
	dynamiccertificates.ControllerRunner // we do not need this today, but it could grow and change in the future
}

type provider struct {
	name string

	// mutex guards all the fields below it
	mutex     sync.RWMutex
	certPEM   []byte
	keyPEM    []byte
	listeners []dynamiccertificates.Listener
}

// New returns an empty Provider. The returned Provider is thread-safe.
func New(name string) Provider {
	return &provider{name: name}
}

func (p *provider) Name() string {
	return p.name // constant after struct initialization and thus does not need locking
}

func (p *provider) CurrentCertKeyContent() (cert []byte, key []byte) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return p.certPEM, p.keyPEM
}

func (p *provider) SetCertKeyContent(certPEM, keyPEM []byte) error {
	// always make sure that we have valid PEM data, otherwise
	// dynamiccertificates.NewUnionCAContentProvider.VerifyOptions will panic
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("%s: attempt to set invalid key pair: %w", p.name, err)
	}

	p.setCertKeyContent(certPEM, keyPEM)

	return nil
}

func (p *provider) UnsetCertKeyContent() {
	p.setCertKeyContent(nil, nil)
}

func (p *provider) setCertKeyContent(certPEM, keyPEM []byte) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.certPEM = certPEM
	p.keyPEM = keyPEM

	for _, listener := range p.listeners {
		listener.Enqueue()
	}
}

func (p *provider) CurrentCABundleContent() []byte {
	ca, _ := p.CurrentCertKeyContent()
	return ca
}

func (p *provider) VerifyOptions() (x509.VerifyOptions, bool) {
	return x509.VerifyOptions{}, false // assume we are unioned via dynamiccertificates.NewUnionCAContentProvider
}

func (p *provider) AddListener(listener dynamiccertificates.Listener) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.listeners = append(p.listeners, listener)
}

func (p *provider) RunOnce() error {
	return nil // no-op, but we want to make sure to stay in sync with dynamiccertificates.ControllerRunner
}

func (p *provider) Run(workers int, stopCh <-chan struct{}) {
	// no-op, but we want to make sure to stay in sync with dynamiccertificates.ControllerRunner
}
