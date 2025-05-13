// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package localuserauthenticator provides a authentication webhook program.
//
// This webhook is meant to be used in demo settings to play around with
// Pinniped. As well, it can come in handy in integration tests.
//
// This webhook is NOT meant for use in production systems.
package localuserauthenticator

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sinformers "k8s.io/client-go/informers"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/controller/apicerts"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/plog"
)

const (
	// This string must match the name of the Namespace declared in the deployment yaml.
	namespace = "local-user-authenticator"
	// This string must match the name of the Service declared in the deployment yaml.
	serviceName = "local-user-authenticator"

	singletonWorker       = 1
	defaultResyncInterval = 3 * time.Minute

	invalidRequest = constable.Error("invalid request")
)

type webhook struct {
	certProvider   dynamiccert.Private
	secretInformer corev1informers.SecretInformer
}

func newWebhook(
	certProvider dynamiccert.Private,
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
	c := ptls.Secure(nil)
	c.GetCertificate = func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		certPEM, keyPEM := w.certProvider.CurrentCertKeyContent()
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		return &cert, err
	}
	server := http.Server{
		Handler:           w,
		TLSConfig:         c,
		ReadHeaderTimeout: 10 * time.Second,
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
			plog.Debug("server exited", "err", err)
		case <-ctx.Done():
			plog.Debug("server context cancelled", "err", ctx.Err())
			if err := server.Shutdown(context.Background()); err != nil {
				plog.Debug("server shutdown failed", "err", err)
			}
		}
	}()

	return nil
}

func (w *webhook) ServeHTTP(rsp http.ResponseWriter, req *http.Request) {
	username, password, err := getUsernameAndPasswordFromRequest(rsp, req)
	if err != nil {
		return
	}
	defer func() { _ = req.Body.Close() }()

	secret, err := w.secretInformer.Lister().Secrets(namespace).Get(username)
	notFound := apierrors.IsNotFound(err)
	if err != nil && !notFound {
		plog.Debug("could not get secret", "err", err)
		rsp.WriteHeader(http.StatusInternalServerError)
		return
	}

	if notFound {
		plog.Debug("user not found")
		respondWithUnauthenticated(rsp)
		return
	}

	passwordMatches := bcrypt.CompareHashAndPassword(
		secret.Data["passwordHash"],
		[]byte(password),
	) == nil
	if !passwordMatches {
		plog.Debug("authentication failed: wrong password")
		respondWithUnauthenticated(rsp)
		return
	}

	groups := []string{}
	groupsBuf := bytes.NewBuffer(secret.Data["groups"])
	if groupsBuf.Len() > 0 {
		groupsCSVReader := csv.NewReader(groupsBuf)
		groups, err = groupsCSVReader.Read()
		if err != nil {
			plog.Debug("could not read groups", "err", err)
			rsp.WriteHeader(http.StatusInternalServerError)
			return
		}
		trimLeadingAndTrailingWhitespace(groups)
	}

	plog.Debug("successful authentication")
	respondWithAuthenticated(rsp, secret.Name, groups)
}

func getUsernameAndPasswordFromRequest(rsp http.ResponseWriter, req *http.Request) (string, string, error) {
	if req.URL.Path != "/authenticate" {
		plog.Debug("received request path other than /authenticate", "path", req.URL.Path)
		rsp.WriteHeader(http.StatusNotFound)
		return "", "", invalidRequest
	}

	if req.Method != http.MethodPost {
		plog.Debug("received request method other than post", "method", req.Method)
		rsp.WriteHeader(http.StatusMethodNotAllowed)
		return "", "", invalidRequest
	}

	if !headerContains(req, "Content-Type", "application/json") {
		plog.Debug("content type is not application/json", "Content-Type", req.Header.Values("Content-Type"))
		rsp.WriteHeader(http.StatusUnsupportedMediaType)
		return "", "", invalidRequest
	}

	if !headerContains(req, "Accept", "application/json") &&
		!headerContains(req, "Accept", "application/*") &&
		!headerContains(req, "Accept", "*/*") {
		plog.Debug("client does not accept application/json", "Accept", req.Header.Values("Accept"))
		rsp.WriteHeader(http.StatusUnsupportedMediaType)
		return "", "", invalidRequest
	}

	if req.Body == nil {
		plog.Debug("invalid nil body")
		rsp.WriteHeader(http.StatusBadRequest)
		return "", "", invalidRequest
	}

	var body authenticationv1beta1.TokenReview
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		plog.Debug("failed to decode body", "err", err)
		rsp.WriteHeader(http.StatusBadRequest)
		return "", "", invalidRequest
	}

	if body.APIVersion != authenticationv1beta1.SchemeGroupVersion.String() {
		plog.Debug("invalid TokenReview apiVersion", "apiVersion", body.APIVersion)
		rsp.WriteHeader(http.StatusBadRequest)
		return "", "", invalidRequest
	}

	if body.Kind != "TokenReview" {
		plog.Debug("invalid TokenReview kind", "kind", body.Kind)
		rsp.WriteHeader(http.StatusBadRequest)
		return "", "", invalidRequest
	}

	tokenSegments := strings.SplitN(body.Spec.Token, ":", 2)
	if len(tokenSegments) != 2 {
		plog.Debug("bad token format in request")
		rsp.WriteHeader(http.StatusBadRequest)
		return "", "", invalidRequest
	}

	return tokenSegments[0], tokenSegments[1], nil
}

func headerContains(req *http.Request, headerName, s string) bool {
	headerValues := req.Header.Values(headerName)
	for i := range headerValues {
		mimeTypes := strings.Split(headerValues[i], ",")
		for _, mimeType := range mimeTypes {
			mediaType, _, _ := mime.ParseMediaType(mimeType)
			if mediaType == s {
				return true
			}
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

	body := authenticationv1beta1.TokenReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "TokenReview",
			APIVersion: authenticationv1beta1.SchemeGroupVersion.String(),
		},
		Status: authenticationv1beta1.TokenReviewStatus{
			Authenticated: false,
		},
	}
	if err := json.NewEncoder(rsp).Encode(body); err != nil {
		plog.Debug("could not encode response", "err", err)
		rsp.WriteHeader(http.StatusInternalServerError)
	}
}

func respondWithAuthenticated(
	rsp http.ResponseWriter,
	username string,
	groups []string,
) {
	rsp.Header().Add("Content-Type", "application/json")
	body := authenticationv1beta1.TokenReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "TokenReview",
			APIVersion: authenticationv1beta1.SchemeGroupVersion.String(),
		},
		Status: authenticationv1beta1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1beta1.UserInfo{
				Username: username,
				Groups:   groups,
			},
		},
	}
	if err := json.NewEncoder(rsp).Encode(body); err != nil {
		plog.Debug("could not encode response", "err", err)
		rsp.WriteHeader(http.StatusInternalServerError)
	}
}

func startControllers(
	ctx context.Context,
	dynamicCertProvider dynamiccert.Private,
	kubeClient kubernetes.Interface,
	kubeInformers k8sinformers.SharedInformerFactory,
) {
	aVeryLongTime := time.Hour * 24 * 365 * 100

	const certsSecretResourceName = "local-user-authenticator-tls-serving-certificate"

	// Create controller manager.
	controllerManager := controllerlib.
		NewManager().
		WithController(
			apicerts.NewCertsManagerController(
				namespace,
				certsSecretResourceName,
				map[string]string{
					"app": "local-user-authenticator",
				},
				kubeClient,
				kubeInformers.Core().V1().Secrets(),
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
				aVeryLongTime,
				"local-user-authenticator CA",
				serviceName,
			),
			singletonWorker,
		).
		WithController(
			apicerts.NewCertsObserverController(
				namespace,
				certsSecretResourceName,
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
	dynamicCertProvider dynamiccert.Private,
	secretInformer corev1informers.SecretInformer,
) error {
	return newWebhook(dynamicCertProvider, secretInformer).start(ctx, l)
}

func waitForSignal() os.Signal {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	return <-signalCh
}

func run(ctx context.Context) error {
	client, err := kubeclient.New()
	if err != nil {
		return fmt.Errorf("cannot create k8s client: %w", err)
	}

	kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(
		client.Kubernetes,
		defaultResyncInterval,
		k8sinformers.WithNamespace(namespace),
	)

	dynamicCertProvider := dynamiccert.NewServingCert("local-user-authenticator-tls-serving-certificate")

	startControllers(ctx, dynamicCertProvider, client.Kubernetes, kubeInformers)
	plog.Debug("controllers are ready")

	//nolint:gosec // Intentionally binding to all network interfaces.
	l, err := net.Listen("tcp", ":8443")
	if err != nil {
		return fmt.Errorf("cannot create listener: %w", err)
	}
	defer func() { _ = l.Close() }()

	err = startWebhook(ctx, l, dynamicCertProvider, kubeInformers.Core().V1().Secrets())
	if err != nil {
		return fmt.Errorf("cannot start webhook: %w", err)
	}
	plog.Debug("webhook is ready", "address", l.Addr().String())

	gotSignal := waitForSignal()
	plog.Debug("webhook exiting", "signal", gotSignal)

	return nil
}

func main() error { // return an error instead of plog.Fatal to allow defer statements to run
	ctx := signalCtx()

	// Hardcode the logging level to debug, since this is a test app and it is very helpful to have
	// verbose logs to debug test failures.
	if err := plog.ValidateAndSetLogLevelAndFormatGlobally(ctx, plog.LogSpec{Level: plog.LevelDebug}); err != nil {
		plog.Fatal(err)
	}

	return run(ctx)
}

func Main() {
	if err := main(); err != nil {
		plog.Fatal(err)
	}
}

func signalCtx() context.Context {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()

		s := <-signalCh
		plog.Debug("saw signal", "signal", s)
	}()

	return ctx
}
