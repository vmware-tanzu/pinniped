// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dynamiccert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	"go.pinniped.dev/internal/plog"
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

var _ Provider = &provider{}

type provider struct {
	// these fields are constant after struct initialization and thus do not need locking
	name string
	isCA bool

	// mutex guards all the fields below it
	mutex     sync.RWMutex
	certPEM   []byte
	keyPEM    []byte
	listeners []dynamiccertificates.Listener
}

// NewServingCert returns a Private that is go routine safe.
// It can only hold key pairs that have IsCA=false.
func NewServingCert(name string) Private {
	return struct {
		Private
	}{
		Private: &provider{name: name},
	}
}

// NewCA returns a Provider that is go routine safe.
// It can only hold key pairs that have IsCA=true.
func NewCA(name string) Provider {
	return &provider{name: name, isCA: true}
}

func (p *provider) Name() string {
	return p.name
}

func (p *provider) CurrentCertKeyContent() (cert []byte, key []byte) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return p.certPEM, p.keyPEM
}

func (p *provider) SetCertKeyContent(certPEM, keyPEM []byte) error {
	// always make sure that we have valid PEM data, otherwise
	// dynamiccertificates.NewUnionCAContentProvider.VerifyOptions will panic
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("%s: attempt to set invalid key pair: %w", p.name, err)
	}

	// these checks should always pass if tls.X509KeyPair did not error
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("%s: key pair has empty cert slice", p.name)
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("%s: failed to parse key pair as x509 cert: %w", p.name, err)
	}

	// confirm that we are not trying to use a CA as a serving cert and vice versa
	if p.isCA != x509Cert.IsCA {
		return fmt.Errorf("%s: attempt to set x509 cert with unexpected IsCA=%v", p.name, x509Cert.IsCA)
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

	// technically this only reads a read lock but we already have the write lock
	for _, listener := range p.listeners {
		listener.Enqueue()
	}
}

func (p *provider) CurrentCABundleContent() []byte {
	if !p.isCA {
		panic("*provider from NewServingCert was cast into wrong CA interface")
	}

	ca, _ := p.CurrentCertKeyContent()
	return ca
}

func (p *provider) VerifyOptions() (x509.VerifyOptions, bool) {
	if !p.isCA {
		panic("*provider from NewServingCert was cast into wrong CA interface")
	}

	plog.Warning("unexpected call to *provider.VerifyOptions; CA union logic is broken")
	return x509.VerifyOptions{}, false // assume we are unioned via dynamiccertificates.NewUnionCAContentProvider
}

func (p *provider) AddListener(listener dynamiccertificates.Listener) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.listeners = append(p.listeners, listener)
}

func (p *provider) RunOnce(_ context.Context) error {
	return nil // no-op, but we want to make sure to stay in sync with dynamiccertificates.ControllerRunner
}

func (p *provider) Run(_ context.Context, workers int) {
	// no-op, but we want to make sure to stay in sync with dynamiccertificates.ControllerRunner
}
