/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"

	"github.com/suzerain-io/placeholder-name/pkg/hello"
)

func main() {
	fmt.Println(hello.NewHelloSayer().SayHello())
}
