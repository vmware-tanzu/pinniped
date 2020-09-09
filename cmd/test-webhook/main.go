/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package main provides a authentication webhook program.
//
// This webhook is meant to be used in demo settings to play around with
// Pinniped. As well, it can come in handy in integration tests.
//
// This webhook is NOT meant for production settings.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	authenticationv1 "k8s.io/api/authentication/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	kubeinformers "k8s.io/client-go/informers"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/suzerain-io/pinniped/internal/provider"
)

const (
	// namespace is the assumed namespace of this webhook. It is hardcoded now for
	// simplicity, but should probably be made configurable in the future.
	namespace = "test-webhook"

	defaultResyncInterval = 3 * time.Minute
)

type webhook struct {
	certProvider   provider.DynamicTLSServingCertProvider
	secretInformer corev1informers.SecretInformer
}

func newWebhook(
	certProvider provider.DynamicTLSServingCertProvider,
	secretInformer corev1informers.SecretInformer,
) *webhook {
	return &webhook{
		certProvider:   certProvider,
		secretInformer: secretInformer,
	}
}

// start runs the webhook in a separate goroutine and returns whether or not the
// webhook was started successfully.
func (w *webhook) start(ctx context.Context, l net.Listener) error {
	server := http.Server{
		Handler: w,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
				certPEM, keyPEM := w.certProvider.CurrentCertKeyContent()
				cert, err := tls.X509KeyPair(certPEM, keyPEM)
				return &cert, err
			},
		},
	}

	errCh := make(chan error)
	go func() {
		// Per ListenAndServeTLS doc, the {cert,key}File parameters can be empty
		// since we want to use the certs from http.Server.TLSConfig.
		errCh <- server.ServeTLS(l, "", "")
	}()

	go func() {
		select {
		case err := <-errCh:
			klog.InfoS("server exited", "err", err)
		case <-ctx.Done():
			klog.InfoS("server context cancelled", "err", ctx.Err())
			if err := server.Shutdown(context.Background()); err != nil {
				klog.InfoS("server shutdown failed", "err", err)
			}
		}
	}()

	return nil
}

func (w *webhook) ServeHTTP(rsp http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	if req.URL.Path != "/authenticate" {
		rsp.WriteHeader(http.StatusNotFound)
		return
	}

	if req.Method != http.MethodPost {
		rsp.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if !contains(req.Header.Values("Content-Type"), "application/json") {
		rsp.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	if !contains(req.Header.Values("Accept"), "application/json") {
		rsp.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	var body authenticationv1.TokenReview
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		klog.InfoS("failed to decode body", "err", err)
		rsp.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenSegments := strings.SplitN(body.Spec.Token, ":", 2)
	if len(tokenSegments) != 2 {
		rsp.WriteHeader(http.StatusBadRequest)
		return
	}
	username := tokenSegments[0]
	password := tokenSegments[1]

	secret, err := w.secretInformer.Lister().Secrets(namespace).Get(username)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		klog.InfoS("could not get secret", "err", err)
		rsp.WriteHeader(http.StatusInternalServerError)
		return
	}

	if notFound {
		respondWithUnauthenticated(rsp)
		return
	}

	passwordMatches := bcrypt.CompareHashAndPassword(
		secret.Data["passwordHash"],
		[]byte(password),
	) == nil
	if !passwordMatches {
		respondWithUnauthenticated(rsp)
	}

	groupsBuf := bytes.NewBuffer(secret.Data["groups"])
	gr := csv.NewReader(groupsBuf)
	groups, err := gr.Read()
	if err != nil {
		klog.InfoS("could not read groups", "err", err)
		rsp.WriteHeader(http.StatusInternalServerError)
		return
	}
	trimSpace(groups)

	respondWithAuthenticated(rsp, secret.ObjectMeta.Name, string(secret.UID), groups)
}

func contains(ss []string, s string) bool {
	for i := range ss {
		if ss[i] == s {
			return true
		}
	}
	return false
}

func trimSpace(ss []string) {
	for i := range ss {
		ss[i] = strings.TrimSpace(ss[i])
	}
}

func respondWithUnauthenticated(rsp http.ResponseWriter) {
	rsp.Header().Add("Content-Type", "application/json")

	body := authenticationv1.TokenReview{
		Status: authenticationv1.TokenReviewStatus{
			Authenticated: false,
		},
	}
	if err := json.NewEncoder(rsp).Encode(body); err != nil {
		klog.InfoS("could not encode response", "err", err)
		rsp.WriteHeader(http.StatusInternalServerError)
	}
}

func respondWithAuthenticated(
	rsp http.ResponseWriter,
	username, uid string,
	groups []string,
) {
	rsp.Header().Add("Content-Type", "application/json")

	body := authenticationv1.TokenReview{
		Status: authenticationv1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1.UserInfo{
				Username: username,
				UID:      uid,
				Groups:   groups,
			},
		},
	}
	if err := json.NewEncoder(rsp).Encode(body); err != nil {
		klog.InfoS("could not encode response", "err", err)
		rsp.WriteHeader(http.StatusInternalServerError)
	}
}

func newK8sClient() (kubernetes.Interface, error) {
	kubeConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
	}

	// Connect to the core Kubernetes API.
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("could not load in-cluster configuration: %w", err)
	}

	return kubeClient, nil
}

func startControllers(ctx context.Context) error {
	return nil
}

func startWebhook(
	ctx context.Context,
	l net.Listener,
	secretInformer corev1informers.SecretInformer,
) error {
	return newWebhook(
		provider.NewDynamicTLSServingCertProvider(),
		secretInformer,
	).start(ctx, l)
}

func waitForSignal() os.Signal {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	return <-signalCh
}

func run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kubeClient, err := newK8sClient()
	if err != nil {
		return fmt.Errorf("cannot create k8s client: %w", err)
	}

	kubeInformers := kubeinformers.NewSharedInformerFactoryWithOptions(
		kubeClient,
		defaultResyncInterval,
		kubeinformers.WithNamespace(namespace),
	)

	if err := startControllers(ctx); err != nil {
		return fmt.Errorf("cannot start controllers: %w", err)
	}
	klog.InfoS("controllers are ready")

	l, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		return fmt.Errorf("cannot create listener: %w", err)
	}
	defer l.Close()

	if err := startWebhook(
		ctx,
		l,
		kubeInformers.Core().V1().Secrets(),
	); err != nil {
		return fmt.Errorf("cannot start webhook: %w", err)
	}
	klog.InfoS("webhook is ready", "address", l.Addr().String())

	signal := waitForSignal()
	klog.InfoS("webhook exiting", "signal", signal)

	return nil
}

func main() {
	if err := run(); err != nil {
		klog.Fatal(err)
	}
}
