/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package constable

var _ error = Error("")

type Error string

func (e Error) Error() string {
	return string(e)
}
