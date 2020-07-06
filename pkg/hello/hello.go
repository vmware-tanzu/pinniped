/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package hello

type HelloSayer interface {
	SayHello() string
}

type helloSayerImpl struct{}

func (helloSayerImpl) SayHello() string { return "hello" }

func NewHelloSayer() HelloSayer {
	return helloSayerImpl{}
}
