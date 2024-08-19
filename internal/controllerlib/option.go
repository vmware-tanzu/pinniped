// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controllerlib

import (
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/workqueue"

	"go.pinniped.dev/internal/plog"
)

type Option func(*controller)

func WithMaxRetries(maxRetries int) Option {
	return func(c *controller) {
		c.maxRetries = maxRetries
	}
}

func WithInitialEvent(key Key) Option {
	return toNaiveRunOpt(func(c *controller) {
		c.queueWrapper.Add(key)
	})
}

func WithRateLimiter(limiter workqueue.TypedRateLimiter[any]) Option {
	return func(c *controller) {
		cfg := workqueue.TypedRateLimitingQueueConfig[any]{
			Name: c.Name(),
		}
		c.queue = workqueue.NewTypedRateLimitingQueueWithConfig(limiter, cfg)
		c.queueWrapper = &queueWrapper{queue: c.queue}
	}
}

func WithRecorder(recorder events.EventRecorder) Option {
	return func(c *controller) {
		c.recorder = recorder
	}
}

func WithInformer(getter InformerGetter, filter Filter, opt InformerOption) Option {
	informer := getter.Informer() // immediately signal that we intend to use this informer in case it is lazily initialized
	return toRunOpt(func(c *controller) {
		if opt.SkipSync && opt.SkipEvents {
			panic(die("cannot skip syncing and event handlers at the same time"))
		}

		if !opt.SkipSync {
			c.cacheSyncs = append(c.cacheSyncs, informer.HasSynced)
		}

		if opt.SkipEvents {
			return
		}

		_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				object := metaOrDie(obj)
				if filter.Add(object) {
					plog.Debug("handling add",
						"controller", c.Name(),
						"namespace", object.GetNamespace(),
						"name", object.GetName(),
						"selfLink", object.GetSelfLink(), // TODO: self link is deprecated so we need to extract the GVR in some other way (using a series of schemes?)
						"kind", fmt.Sprintf("%T", object),
					)
					c.add(filter, object)
				}
			},
			UpdateFunc: func(oldObj, newObj any) {
				oldObject := metaOrDie(oldObj)
				newObject := metaOrDie(newObj)
				if filter.Update(oldObject, newObject) {
					plog.Debug("handling update",
						"controller", c.Name(),
						"namespace", newObject.GetNamespace(),
						"name", newObject.GetName(),
						"selfLink", newObject.GetSelfLink(), // TODO: self link is deprecated so we need to extract the GVR in some other way (using a series of schemes?)
						"kind", fmt.Sprintf("%T", newObject),
					)
					c.add(filter, newObject)
				}
			},
			DeleteFunc: func(obj any) {
				accessor, err := meta.Accessor(obj)
				if err != nil {
					tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
					if !ok {
						utilruntime.HandleError(fmt.Errorf("%s: could not get object from tombstone: %+v", c.Name(), obj))
						return
					}
					accessor, err = meta.Accessor(tombstone.Obj)
					if err != nil {
						utilruntime.HandleError(fmt.Errorf("%s: tombstone contained object that is not an accessor: %+v", c.Name(), obj))
						return
					}
				}
				if filter.Delete(accessor) {
					plog.Debug("handling delete",
						"controller", c.Name(),
						"namespace", accessor.GetNamespace(),
						"name", accessor.GetName(),
						"selfLink", accessor.GetSelfLink(), // TODO: self link is deprecated so we need to extract the GVR in some other way (using a series of schemes?)
						"kind", fmt.Sprintf("%T", accessor),
					)
					c.add(filter, accessor)
				}
			},
		})
		if err != nil {
			// Shouldn't really happen.
			panic(die(fmt.Sprintf("got error from AddEventHandler: %s", err.Error())))
		}
	})
}

// toRunOpt guarantees that an Option only runs once on the first call to Run (and not New), even if a controller is stopped and restarted.
func toRunOpt(opt Option) Option {
	return toOnceOpt(toNaiveRunOpt(opt))
}

// toNaiveRunOpt guarantees that an Option only runs on calls to Run (and not New), even if a controller is stopped and restarted.
func toNaiveRunOpt(opt Option) Option {
	return func(c *controller) {
		if c.run {
			opt(c)
			return
		}
		c.runOpts = append(c.runOpts, opt)
	}
}

// toOnceOpt guarantees that an Option only runs once.
func toOnceOpt(opt Option) Option {
	var once sync.Once
	return func(c *controller) {
		once.Do(func() {
			opt(c)
		})
	}
}

func metaOrDie(obj any) metav1.Object {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		panic(err) // this should never happen
	}
	return accessor
}
