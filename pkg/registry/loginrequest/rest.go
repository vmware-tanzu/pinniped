package loginrequest

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/registry/rest"

	placeholderapi "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder"
)

var (
	_ rest.Creater                 = &REST{}
	_ rest.NamespaceScopedStrategy = &REST{}
	_ rest.Scoper                  = &REST{}
	_ rest.Storage                 = &REST{}
)

func NewREST(webhook authenticator.Token) *REST {
	return &REST{
		webhook: webhook,
	}
}

type REST struct {
	webhook authenticator.Token
}

func (r *REST) New() runtime.Object {
	return &placeholderapi.LoginRequest{}
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	loginRequest, ok := obj.(*placeholderapi.LoginRequest)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not a LoginRequest: %#v", obj))
	}

	// TODO move into a validation function, check .spec.type, write unit tests, etc
	token := loginRequest.Spec.Token
	if token == nil || len(token.Value) == 0 {
		errs := field.ErrorList{field.Required(field.NewPath("spec", "token", "value"), "token must be supplied")}
		return nil, apierrors.NewInvalid(placeholderapi.Kind(loginRequest.Kind), "", errs)
	}

	// let dynamic admission webhooks have a chance to validate (but not mutate) as well
	// TODO are we okay with admission webhooks being able to see tokens?
	if createValidation != nil {
		if err := createValidation(ctx, obj.DeepCopyObject()); err != nil {
			return nil, err
		}
	}

	// just a sanity check, not sure how to honor a dry run on a virtual API
	if options != nil {
		if len(options.DryRun) != 0 {
			errs := field.ErrorList{field.NotSupported(field.NewPath("dryRun"), options.DryRun, nil)}
			return nil, apierrors.NewInvalid(placeholderapi.Kind(loginRequest.Kind), "", errs)

		}
	}

	// the incoming context could have an audience attached to it technically
	// sine we do not want to handle audiences right now, do not pass it through directly
	// instead we just propagate cancellation of the parent context
	cancelCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-cancelCtx.Done():
		}
	}()

	// resp, ok, err := r.webhook.AuthenticateToken(cancelCtx, token.Value)

	// TODO put something reasonable here
	// make a new object so that we do not return the original token in the response
	out := &placeholderapi.LoginRequest{
		Status: placeholderapi.LoginRequestStatus{
			ExpirationTimestamp:   nil,
			Token:                 "snorlax",
			ClientCertificateData: "",
			ClientKeyData:         "",
		},
	}

	return out, nil
}
