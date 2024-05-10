// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/events"

	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/controllerlib/test/integration/examplecontroller/api"
)

func TestNewExampleCreatingController(t *testing.T) {
	secretsGVR := schema.GroupVersionResource{Version: "v1", Resource: "secrets"}

	type args struct {
		services   []*corev1.Service
		secrets    []*corev1.Secret
		secretData string
	}
	type keyErr struct {
		key controllerlib.Key
		err error
	}
	tests := []struct {
		name        string
		args        args
		wantActions []coretesting.Action
		wantKeyErrs []keyErr
	}{
		{
			name: "service has annotation but secret does not exist",
			args: args{
				services: []*corev1.Service{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ns-1",
							Name:      "service-1",
							Annotations: map[string]string{
								api.SecretNameAnnotation: "secret-1",
							},
							UID: "0001",
						},
					},
				},
				secretData: "foo-secret-1",
			},
			wantKeyErrs: []keyErr{
				{
					key: controllerlib.Key{
						Namespace: "ns-1",
						Name:      "service-1",
					},
					err: nil, // we expect no error with this key
				},
			},
			wantActions: []coretesting.Action{
				coretesting.NewCreateAction(secretsGVR, "ns-1", &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "secret-1",
						Namespace: "ns-1",
						Annotations: map[string]string{
							api.ServiceUIDAnnotation:  "0001",
							api.ServiceNameAnnotation: "service-1",
						},
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "v1",
								Kind:       "Service",
								Name:       "service-1",
								UID:        "0001",
							},
						},
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						api.SecretDataKey: []byte("foo-secret-1"),
					},
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kubeClient := fake.NewSimpleClientset()
			for i := range tt.args.services {
				service := tt.args.services[i]
				err := kubeClient.Tracker().Add(service)
				require.NoError(t, err)
			}
			for i := range tt.args.secrets {
				secret := tt.args.secrets[i]
				err := kubeClient.Tracker().Add(secret)
				require.NoError(t, err)
			}

			recorder := events.NewEventBroadcasterAdapter(kubeClient).NewRecorder("example-controller")
			kubeInformers := informers.NewSharedInformerFactory(kubeClient, 0)

			creatingController := NewExampleCreatingController(
				kubeInformers.Core().V1().Services(),
				kubeInformers.Core().V1().Secrets(),
				kubeClient.CoreV1(),
				recorder,
				tt.args.secretData,
			)

			keyErrs := make(chan keyErr)
			controllerlib.TestWrap(t, creatingController, func(syncer controllerlib.Syncer) controllerlib.Syncer {
				return controllerlib.SyncFunc(func(ctx controllerlib.Context) error {
					err := syncer.Sync(ctx)

					keyErrs <- keyErr{
						key: ctx.Key,
						err: err,
					}

					return err
				})
			})

			// a different approach would be to use TestSync and run each iteration manually:
			//
			// err := controller.TestSync(t, c, ...)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			kubeInformers.Start(ctx.Done())
			go creatingController.Run(ctx, 5) // TODO maybe only use one worker?

			var actualKeyErrs []keyErr
		done:
			for {
				select {
				case key := <-keyErrs:
					actualKeyErrs = append(actualKeyErrs, key)

				case <-time.After(3 * time.Second):
					// this assumes that calls to Sync are never more than three seconds apart
					// we have five workers so there is little chance they all hang around doing nothing for that long
					break done
				}
			}

			// TODO: Figure out how to capture actions from informers
			// TODO: I think we need some more fancy order independent equal comparison here

			require.Equal(t, tt.wantKeyErrs, actualKeyErrs)

			// ignore the discovery call from the event recorder and the list/watch from both informers (first five events)
			require.Equal(t, tt.wantActions, kubeClient.Actions()[5:])
		})
	}
}
