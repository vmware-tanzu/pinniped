/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package provider

type DynamicTLSServingCertProvider struct {
	CertPEM []byte
	KeyPEM  []byte
}

func (*DynamicTLSServingCertProvider) Name() string {
	return "DynamicTLSServingCertProvider"
}

func (p *DynamicTLSServingCertProvider) CurrentCertKeyContent() (cert []byte, key []byte) {
	return p.CertPEM, p.KeyPEM
}
