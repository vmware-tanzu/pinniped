/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package hello

import (
	"testing"
)

func TestHelloSayerImpl_SayHello(t *testing.T) {
	actualGreeting := NewHelloSayer().SayHello()
	if actualGreeting != "hello" {
		t.Errorf("expected to say hello but said %v", actualGreeting)
	}
}
