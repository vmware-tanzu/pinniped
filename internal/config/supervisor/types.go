// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisor

// Config contains knobs to setup an instance of the Pinniped Supervisor.
type Config struct {
	Labels      map[string]string `json:"labels"`
	NamesConfig NamesConfigSpec   `json:"names"`
}

// NamesConfigSpec configures the names of some Kubernetes resources for the Supervisor.
type NamesConfigSpec struct {
	DefaultTLSCertificateSecret string `json:"defaultTLSCertificateSecret"`
}
