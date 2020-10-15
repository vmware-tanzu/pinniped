// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisor

// Config contains knobs to setup an instance of the Pinniped Supervisor.
type Config struct {
	Labels map[string]string `json:"labels"`
}
