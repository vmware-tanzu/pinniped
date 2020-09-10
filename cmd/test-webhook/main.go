/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package main provides a authentication webhook program.
//
// This webhook is meant to be used in demo settings to play around with
// Pinniped. As well, it can come in handy in integration tests.
//
// This webhook is NOT meant for use in production systems.
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

	"github.com/suzerain-io/pinniped/internal/controller/apicerts"
	"github.com/suzerain-io/pinniped/internal/controllerlib"
	"github.com/suzerain-io/pinniped/internal/provider"
)

const (
	// This string must match the name of the Namespace declared in the deployment yaml.
	namespace = "test-webhook"
	// This string must match the name of the Service declared in the deployment yaml.
	serviceName = "test-webhook"

	// TODO there must be a better way to get this specific json result string without needing to hardcode it
	unauthenticatedResponse = `{"apiVersion":"authentication.k8s.io/v1beta1","kind":"TokenReview","status":{"authenticated":false}}`

	// TODO there must be a better way to get this specific json result string without needing to hardcode it
	authenticatedResponseTemplate = `{"apiVersion":"authentication.k8s.io/v1beta1","kind":"TokenReview","status":{"authenticated":true,"user":{"username":"%s","uid":"%s","groups":%s}}}`

	singletonWorker       = 1
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
		klog.InfoS("received request path other than /authenticate", "path", req.URL.Path)
		rsp.WriteHeader(http.StatusNotFound)
		return
	}

	if req.Method != http.MethodPost {
		klog.InfoS("received request method other than post", "method", req.Method)
		rsp.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if !contains(req.Header.Values("Content-Type"), "application/json") {
		klog.InfoS("wrong content type", "Content-Type", req.Header.Values("Content-Type"))
		rsp.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	if !contains(req.Header.Values("Accept"), "application/json") {
		klog.InfoS("wrong accept type", "Accept", req.Header.Values("Accept"))
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
		klog.InfoS("bad token format in request")
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
		klog.InfoS("user not found")
		respondWithUnauthenticated(rsp)
		return
	}

	passwordMatches := bcrypt.CompareHashAndPassword(
		secret.Data["passwordHash"],
		[]byte(password),
	) == nil
	if !passwordMatches {
		klog.InfoS("invalid password in request")
		respondWithUnauthenticated(rsp)
		return
	}

	groups := []string{}
	groupsBuf := bytes.NewBuffer(secret.Data["groups"])
	if groupsBuf.Len() > 0 {
		groupsCSVReader := csv.NewReader(groupsBuf)
		groups, err = groupsCSVReader.Read()
		if err != nil {
			klog.InfoS("could not read groups", "err", err)
			rsp.WriteHeader(http.StatusInternalServerError)
			return
		}
		trimLeadingAndTrailingWhitespace(groups)
	}

	klog.InfoS("successful authentication")
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

func trimLeadingAndTrailingWhitespace(ss []string) {
	for i := range ss {
		ss[i] = strings.TrimSpace(ss[i])
	}
}

func respondWithUnauthenticated(rsp http.ResponseWriter) {
	rsp.Header().Add("Content-Type", "application/json")
	_, _ = rsp.Write([]byte(unauthenticatedResponse))
}

func respondWithAuthenticated(
	rsp http.ResponseWriter,
	username, uid string,
	groups []string,
) {
	rsp.Header().Add("Content-Type", "application/json")
	groupsJSONBytes, err := json.Marshal(groups)
	if err != nil {
		klog.InfoS("could not encode response", "err", err)
		rsp.WriteHeader(http.StatusInternalServerError)
		return
	}
	jsonBody := fmt.Sprintf(authenticatedResponseTemplate, username, uid, groupsJSONBytes)
	_, _ = rsp.Write([]byte(jsonBody))
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

func startControllers(
	ctx context.Context,
	dynamicCertProvider provider.DynamicTLSServingCertProvider,
	kubeClient kubernetes.Interface,
	kubeInformers kubeinformers.SharedInformerFactory,
) {
	aVeryLongTime := time.Hour * 24 * 365 * 100

	// Create controller manager.
	controllerManager := controllerlib.
		NewManager().
		WithController(
			apicerts.NewCertsManagerController(
				namespace,
				kubeClient,
				kubeInformers.Core().V1().Secrets(),
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
				aVeryLongTime,
				"test-webhook CA",
				serviceName,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsObserverController(
				namespace,
				dynamicCertProvider,
				kubeInformers.Core().V1().Secrets(),
				controllerlib.WithInformer,
			),
			singletonWorker,
		)

	kubeInformers.Start(ctx.Done())

	go controllerManager.Start(ctx)
}

func startWebhook(
	ctx context.Context,
	l net.Listener,
	dynamicCertProvider provider.DynamicTLSServingCertProvider,
	secretInformer corev1informers.SecretInformer,
) error {
	return newWebhook(dynamicCertProvider, secretInformer).start(ctx, l)
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

	dynamicCertProvider := provider.NewDynamicTLSServingCertProvider()

	startControllers(ctx, dynamicCertProvider, kubeClient, kubeInformers)
	klog.InfoS("controllers are ready")

	//nolint: gosec
	l, err := net.Listen("tcp", ":443")
	if err != nil {
		return fmt.Errorf("cannot create listener: %w", err)
	}
	defer l.Close()

	err = startWebhook(ctx, l, dynamicCertProvider, kubeInformers.Core().V1().Secrets())
	if err != nil {
		return fmt.Errorf("cannot start webhook: %w", err)
	}
	klog.InfoS("webhook is ready", "address", l.Addr().String())

	gotSignal := waitForSignal()
	klog.InfoS("webhook exiting", "signal", gotSignal)

	return nil
}

func main() {
	if err := run(); err != nil {
		klog.Fatal(err)
	}
}
