// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controllerlib

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/workqueue"

	"go.pinniped.dev/internal/plog"
)

// Controller interface represents a runnable Kubernetes controller.
// Cancelling the context passed will cause the controller to shutdown.
// Number of workers determine how much parallel the job processing should be.
type Controller interface {
	// Run runs the controller and blocks until the controller is finished.
	// Number of workers can be specified via workers parameter.
	// This function will return when all internal loops are finished.
	// Note that having more than one worker usually means handing parallelization of Sync().
	Run(ctx context.Context, workers int)

	// Name returns the controller name string.
	Name() string

	// The methods below should only be called during tests via the Test* functions.

	// sync contains the main controller logic.
	// This can be used in unit tests to exercise the Syncer by directly calling it.
	sync(ctx Context) error

	// wrap wraps the main controller logic provided via the Syncer.
	// This can be used in tests to synchronize asynchronous events as seen by a running controller.
	// The wrapping must be done after New is called and before Run is called.
	wrap(wrapper SyncWrapperFunc)

	// These are called by the Run() method but also need to be called by Test* functions sometimes.
	waitForCacheSyncWithTimeout() bool
	invokeAllRunOpts()
}

var _ Controller = &controller{}

type Config struct {
	Name   string
	Syncer Syncer
}

func New(config Config, opts ...Option) Controller {
	c := &controller{
		config: config,
	}

	// set up defaults
	WithRateLimiter(workqueue.DefaultTypedControllerRateLimiter[any]())(c)
	WithRecorder(klogRecorder{})(c)

	for _, opt := range opts {
		opt(c)
	}

	return c
}

type controller struct {
	config Config

	queue        workqueue.TypedRateLimitingInterface[any]
	queueWrapper Queue
	maxRetries   int
	recorder     events.EventRecorder

	run     bool
	runOpts []Option

	cacheSyncs []cache.InformerSynced
}

func (c *controller) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash(crash) // prevent panics from killing the process

	plog.Debug("starting controller", "controller", c.Name(), "workers", workers)

	c.invokeAllRunOpts()

	if !c.waitForCacheSyncWithTimeout() {
		panic(die(fmt.Sprintf("%s: timed out waiting for caches to sync", c.Name())))
	}

	var workerWg sync.WaitGroup

	// workerContext is used to track and initiate worker shutdown
	workerContext, workerContextCancel := context.WithCancel(context.Background())

	defer func() {
		plog.Debug("starting to shut down controller workers", "controller", c.Name(), "workers", workers)
		c.queue.ShutDown()    // shutdown the controller queue first
		workerContextCancel() // cancel the worker context, which tell workers to initiate shutdown

		// Wait for all workers to finish their job.
		// at this point the Run() can hang and callers have to implement the logic that will kill
		// this controller (SIGKILL).
		workerWg.Wait()
		plog.Debug("all workers have been terminated, shutting down", "controller", c.Name(), "workers", workers)
	}()

	for i := 1; i <= workers; i++ {
		idx := i
		plog.Debug("starting worker", "controller", c.Name(), "worker", idx)
		workerWg.Add(1)
		go func() {
			defer utilruntime.HandleCrash(crash) // prevent panics from killing the process
			defer func() {
				plog.Debug("shutting down worker", "controller", c.Name(), "worker", idx)
				workerWg.Done()
			}()
			c.runWorker(workerContext)
		}()
	}

	plog.Debug("controller started", "controller", c.Name(), "workers", workers)
	<-ctx.Done() // wait for controller context to be cancelled
	plog.Debug("controller context cancelled, next will terminate workers", "controller", c.Name(), "workers", workers)
}

func (c *controller) invokeAllRunOpts() {
	c.run = true
	for _, opt := range c.runOpts {
		opt(c)
	}
}

func (c *controller) Name() string {
	return c.config.Name
}

func (c *controller) sync(ctx Context) error {
	return c.config.Syncer.Sync(ctx)
}

func (c *controller) wrap(wrapper SyncWrapperFunc) {
	c.runOpts = append(c.runOpts, toRunOpt(func(c *controller) {
		c.config.Syncer = wrapper(c.config.Syncer)
	}))
}

func (c *controller) waitForCacheSyncWithTimeout() bool {
	// prevent us from blocking forever due to a broken informer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	return cache.WaitForCacheSync(ctx.Done(), c.cacheSyncs...)
}

func (c *controller) add(filter Filter, object metav1.Object) {
	key := filter.Parent(object)
	c.queueWrapper.Add(key)
}

// runWorker runs a single worker
// The worker is asked to terminate when the passed context is cancelled.
func (c *controller) runWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			c.processNextWorkItem(ctx)
		}
	}
}

func (c *controller) processNextWorkItem(ctx context.Context) {
	queueKey, quit := c.queue.Get()
	if quit {
		return
	}

	key := queueKey.(Key)
	defer c.queue.Done(key)

	syncCtx := Context{
		Context:  ctx,
		Name:     c.Name(),
		Key:      key,
		Queue:    c.queueWrapper,
		Recorder: c.recorder,
	}

	err := c.sync(syncCtx)
	c.handleKey(key, err)
}

func (c *controller) handleKey(key Key, err error) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	retryForever := c.maxRetries <= 0
	shouldRetry := retryForever || c.queue.NumRequeues(key) < c.maxRetries

	if !shouldRetry {
		utilruntime.HandleError(fmt.Errorf("%s: dropping key %v out of the queue: %w", c.Name(), key, err))
		c.queue.Forget(key)
		return
	}

	if errors.Is(err, ErrSyntheticRequeue) {
		// logging this helps detecting wedged controllers with missing pre-requirements
		plog.Debug("requested synthetic requeue", "controller", c.Name(), "key", key)
	} else {
		utilruntime.HandleError(fmt.Errorf("%s: %v failed with: %w", c.Name(), key, err))
	}

	c.queue.AddRateLimited(key)
}
