/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package controller

type die string

func crash(i interface{}) {
	mustDie, ok := i.(die)
	if ok {
		panic(string(mustDie))
	}
}
