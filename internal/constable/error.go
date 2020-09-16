// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package constable

var _ error = Error("")

type Error string

func (e Error) Error() string {
	return string(e)
}
