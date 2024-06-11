// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controllerlib

type die string

func crash(i any) {
	mustDie, ok := i.(die)
	if ok {
		panic(string(mustDie))
	}
}
