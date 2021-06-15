// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package authorizationcode

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"k8s.io/apimachinery/pkg/api/errors"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/fositestorage"
	"go.pinniped.dev/internal/oidc/staticclient"
)

const (
	TypeLabelValue = "authcode"

	ErrInvalidAuthorizeRequestData    = constable.Error("authorization request data must be present")
	ErrInvalidAuthorizeRequestVersion = constable.Error("authorization request data has wrong version")

	authorizeCodeStorageVersion = "1"
)

var _ oauth2.AuthorizeCodeStorage = &authorizeCodeStorage{}

type authorizeCodeStorage struct {
	storage crud.Storage
}

type AuthorizeCodeSession struct {
	Active  bool            `json:"active"`
	Request *fosite.Request `json:"request"`
	Version string          `json:"version"`
}

func New(secrets corev1client.SecretInterface, clock func() time.Time, sessionStorageLifetime time.Duration) oauth2.AuthorizeCodeStorage {
	return &authorizeCodeStorage{storage: crud.New(TypeLabelValue, secrets, clock, sessionStorageLifetime)}
}

func (a *authorizeCodeStorage) CreateAuthorizeCodeSession(ctx context.Context, signature string, requester fosite.Requester) error {
	// This conversion assumes that we do not wrap the default type in any way
	// i.e. we use the default fosite.OAuth2Provider.NewAuthorizeRequest implementation
	// note that because this type is serialized and stored in Kube, we cannot easily change the implementation later
	request, err := fositestorage.ValidateAndExtractAuthorizeRequest(requester)
	if err != nil {
		return err
	}

	// Note, in case it is helpful, that Hydra stores specific fields from the requester:
	//  request ID
	//  requestedAt
	//  OAuth client ID
	//  requested scopes, granted scopes
	//  requested audience, granted audience
	//  url encoded request form
	//  session as JSON bytes with (optional) encryption
	//  session subject
	//  consent challenge from session which is the identifier ("authorization challenge")
	//      of the consent authorization request. It is used to identify the session.
	//  signature for lookup in the DB

	_, err = a.storage.Create(ctx, signature, &AuthorizeCodeSession{Active: true, Request: request, Version: authorizeCodeStorageVersion}, nil)
	return err
}

func (a *authorizeCodeStorage) GetAuthorizeCodeSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	// Note, in case it is helpful, that Hydra:
	//  - uses the incoming fosite.Session to provide the type needed to json.Unmarshal their session bytes
	//  - gets the client from its DB as a concrete type via client ID, the hydra memory client just validates that the
	//    client ID exists
	//  - hydra uses the sha512.Sum384 hash of signature when using JWT as access token to reduce length

	session, _, err := a.getSession(ctx, signature)

	// we need to always pass both the request and error back
	if session == nil {
		return nil, err
	}

	return session.Request, err
}

func (a *authorizeCodeStorage) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	session, rv, err := a.getSession(ctx, signature)
	if err != nil {
		return err
	}

	session.Active = false
	if _, err := a.storage.Update(ctx, signature, rv, session); err != nil {
		if errors.IsConflict(err) {
			return &errSerializationFailureWithCause{cause: err}
		}
		return err
	}

	return nil
}

func (a *authorizeCodeStorage) getSession(ctx context.Context, signature string) (*AuthorizeCodeSession, string, error) {
	session := NewValidEmptyAuthorizeCodeSession()
	rv, err := a.storage.Get(ctx, signature, session)

	if errors.IsNotFound(err) {
		return nil, "", fosite.ErrNotFound.WithWrap(err).WithDebug(err.Error())
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to get authorization code session for %s: %w", signature, err)
	}

	if version := session.Version; version != authorizeCodeStorageVersion {
		return nil, "", fmt.Errorf("%w: authorization code session for %s has version %s instead of %s",
			ErrInvalidAuthorizeRequestVersion, signature, version, authorizeCodeStorageVersion)
	}

	if session.Request.ID == "" {
		return nil, "", fmt.Errorf("malformed authorization code session for %s: %w", signature, ErrInvalidAuthorizeRequestData)
	}

	// we must return the session in this case to allow fosite to revoke the associated tokens
	if !session.Active {
		return session, rv, fmt.Errorf("authorization code session for %s has already been used: %w", signature, fosite.ErrInvalidatedAuthorizeCode)
	}

	return session, rv, nil
}

func NewValidEmptyAuthorizeCodeSession() *AuthorizeCodeSession {
	return &AuthorizeCodeSession{
		Request: &fosite.Request{
			Client:  &staticclient.PinnipedCLI{},
			Session: &openid.DefaultSession{},
		},
	}
}

var _ interface {
	Is(error) bool
	Unwrap() error
	error
} = &errSerializationFailureWithCause{}

type errSerializationFailureWithCause struct {
	cause error
}

func (e *errSerializationFailureWithCause) Is(err error) bool {
	return stderrors.Is(fosite.ErrSerializationFailure, err)
}

func (e *errSerializationFailureWithCause) Unwrap() error {
	return e.cause
}

func (e *errSerializationFailureWithCause) Error() string {
	return fmt.Sprintf("%s: %s", fosite.ErrSerializationFailure, e.cause)
}

// ExpectedAuthorizeCodeSessionJSONFromFuzzing is used for round tripping tests.
// It is exported to allow integration tests to use it.
const ExpectedAuthorizeCodeSessionJSONFromFuzzing = `{
		"active": true,
		"request": {
			"id": "曑x螠Gæ鄋楨",
			"requestedAt": "2082-11-10T18:36:11.627253638Z",
			"client": {
				"id": "pinniped-cli"
			},
			"scopes": [
				":Ǌ¸Ɣ8(黋馛ÄRɴJa¶z",
				";",
				"刑ǖ枭kʍ"
			],
			"grantedScopes": [
				"厦ȳ",
				"魿A",
				"ʊXĝ"
			],
			"form": {
				"Ɛ课*ōǔŭe[u@阽": [
					"C棊^/_Tø侔cʝl鼓[ò銱Hp",
					"唡ɸğƎ\u0026胢輢Ƈĵƚĸ"
				],
				"攉çɟȘ¨/湹ĉ優蒼ĊɌț": [
					"蕫V頔Lʏ努ĴKǼz唐W6ɻ橩斚薛"
				]
			},
			"session": {
				"Claims": {
					"JTI": "jA9;焋Ēƕ膊艥1ƶ埐祷錏交鲑趀Ȁ;",
					"Issuer": "w簴ƿʥ",
					"Subject": "蹗ĽǙ澅j翕q骽ļȗĺ",
					"Audience": [
						",JwwƐ\u003c",
						"ɮ$Ól4Ȟ"
					],
					"Nonce": ",Q7钎漡臧n",
					"ExpiresAt": "2059-03-29T04:28:16.806648832Z",
					"IssuedAt": "2070-10-23T09:40:05.695297861Z",
					"RequestedAt": "1971-09-16T08:16:07.666691628Z",
					"AuthTime": "2002-04-24T21:10:59.715265983Z",
					"AccessTokenHash": "+v,淬Ʋ4D",
					"AuthenticationContextClassReference": "bǕOOF(ưƓǴ罷ǹ~]",
					"AuthenticationMethodsReference": "'MR拍Á",
					"CodeHash": "絹b垇IŕĩǀŻQ'k頂箨",
					"Extra": {
						"u4銈ɓ啶#昏Q遐*\\髎bŸ": 1262400391,
						"慂UFƼĮǡ鑻Z": {
							"Ć厦駳骪l拁乖¡J¿Ƈ妔Mʑ": {
								"#碓Ɏ": {
									"ƍdÚ慂+槰蚪": false
								},
								"¥": null
							},
							"ǟ褾攚ŝ": [
								3419218499
							]
						}
					}
				},
				"Headers": {
					"Extra": {
						"/槱黧郛ißɓ礐jµ筁ƿyJǽȭ$奍囀": 2625458941,
						"悷鵱": {
							"舸*ɲ3@": [
								3950865152
							],
							"行": {
								"ǆ霋Ɔ輡5ȏ樛ȧ.mĔ櫓Ǩ療": {
									"Ǉ/": false
								},
								"囡莒汗狲N": null
							}
						}
					}
				},
				"ExpiresAt": {
					"ȗɉY妶": "2021-12-29T17:12:46.958686405Z",
					"潠[ĝU噤'": "2049-07-17T23:15:11.66686771Z"
				},
				"Username": "ùŶ褰ʎɰ癟VĎĢ婄",
				"Subject": "ļ攬林Ñz焁糳¿o\u003eQ"
			},
			"requestedAudience": [
				"翑",
				"1#锰劝旣樎Ȱ",
				"Ǘū稖咾鎅ǸÖ绝"
			],
			"grantedAudience": [
				"FǊĆw"
			]
		},
		"version": "1"
	}`
