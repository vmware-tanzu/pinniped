// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

type Verb interface {
	verb() // private method to prevent creation of verbs outside this package
}

const (
	VerbCreate           verb = "create"
	VerbUpdate           verb = "update"
	VerbDelete           verb = "delete"
	VerbDeleteCollection verb = "deletecollection"
	VerbGet              verb = "get"
	VerbList             verb = "list"
	VerbWatch            verb = "watch"
	VerbPatch            verb = "patch"

	VerbProxy verb = "proxy" // proxy unsupported for now
)

var _, _ Verb = VerbGet, verb("")

type verb string

func (verb) verb() {}
