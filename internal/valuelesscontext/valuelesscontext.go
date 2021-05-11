// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package valuelesscontext

import "context"

func New(ctx context.Context) context.Context {
	return valuelessContext{Context: ctx}
}

type valuelessContext struct{ context.Context }

func (valuelessContext) Value(interface{}) interface{} { return nil }
