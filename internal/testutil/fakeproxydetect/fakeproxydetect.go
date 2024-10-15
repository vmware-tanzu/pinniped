// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package fakeproxydetect

import "go.pinniped.dev/internal/proxydetect"

type FakeProxyDetect struct {
	returnBool   bool
	returnErr    error
	numCalls     int
	receivedHost string
}

var _ proxydetect.ProxyDetect = (*FakeProxyDetect)(nil)

func (f *FakeProxyDetect) UsingProxyForHost(host string) (bool, error) {
	f.numCalls++
	f.receivedHost = host
	return f.returnBool, f.returnErr
}

func (f *FakeProxyDetect) ReceivedHostDuringMostRecentInvocation() string {
	return f.receivedHost
}

func (f *FakeProxyDetect) NumberOfInvocations() int {
	return f.numCalls
}

func New(returnBool bool, returnErr error) *FakeProxyDetect {
	return &FakeProxyDetect{
		returnBool: returnBool,
		returnErr:  returnErr,
	}
}
