// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controllerlib

import (
	"context"
	"sync"

	"go.pinniped.dev/internal/plog"
)

type Manager interface {
	Start(ctx context.Context)
	WithController(controller Controller, workers int) Manager
}

func NewManager() Manager {
	return &controllerManager{}
}

// runnableController represents single controller runnable configuration.
type runnableController struct {
	controller Controller
	workers    int
}

type controllerManager struct {
	controllers []runnableController
}

var _ Manager = &controllerManager{}

func (c *controllerManager) WithController(controller Controller, workers int) Manager {
	c.controllers = append(c.controllers, runnableController{
		controller: controller,
		workers:    workers,
	})
	return c
}

// Start will run all managed controllers and block until all controllers shutdown.
// When the context passed is cancelled, all controllers are signalled to shutdown.
func (c *controllerManager) Start(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(len(c.controllers))
	for i := range c.controllers {
		idx := i
		go func() {
			r := c.controllers[idx]
			defer plog.Debug("controller terminated", "controller", r.controller.Name())
			defer wg.Done()
			r.controller.Run(ctx, r.workers)
		}()
	}
	wg.Wait()
}
