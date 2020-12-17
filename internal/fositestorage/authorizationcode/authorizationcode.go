// Copyright 2020 the Pinniped contributors. All Rights Reserved.
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
			Client:  &fosite.DefaultOpenIDConnectClient{},
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
		  "id": ":Ǌ¸Ɣ8(黋馛ÄRɴJa¶z",
		  "client_secret": "UQ==",
		  "redirect_uris": [
			"ǖ枭kʍ切厦ȳ箦;¥ʊXĝ奨誷傥祩d",
			"zŇZ",
			"優蒼ĊɌț訫ǄǽeʀO2ƚ&N"
		  ],
		  "grant_types": [
			"唐W6ɻ橩斚薛ɑƐ"
		  ],
		  "response_types": [
			"w",
			"ǔŭe[u@阽羂ŷ-Ĵ½輢OÅ濲喾H"
		  ],
		  "scopes": [
			"G螩歐湡ƙı唡ɸğƎ&胢輢Ƈĵƚ"
		  ],
		  "audience": [
			"ě"
		  ],
		  "public": false,
		  "jwks_uri": "o*泞羅ʘ Ⱦķ瀊垰7ã\")",
		  "jwks": {
			"keys": [
			  {
				"kty": "OKP",
				"crv": "Ed25519",
				"x": "nK9xgX_iN7u3u_i8YOO7ZRT_WK028Vd_nhtsUu7Eo6E",
				"x5u": {
				  "Scheme": "",
				  "Opaque": "",
				  "User": null,
				  "Host": "",
				  "Path": "",
				  "RawPath": "",
				  "ForceQuery": false,
				  "RawQuery": "",
				  "Fragment": "",
				  "RawFragment": ""
				}
			  },
			  {
				"kty": "OKP",
				"crv": "Ed25519",
				"x": "UbbswQgzWhfGCRlwQmMp6fw_HoIoqkIaKT-2XN2fuYU",
				"x5u": {
				  "Scheme": "",
				  "Opaque": "",
				  "User": null,
				  "Host": "",
				  "Path": "",
				  "RawPath": "",
				  "ForceQuery": false,
				  "RawQuery": "",
				  "Fragment": "",
				  "RawFragment": ""
				}
			  }
			]
		  },
		  "token_endpoint_auth_method": "ƿʥǟȒ伉<x¹T鼓c吏",
		  "request_uris": [
			"Ć捘j]=谅ʑɑɮ$Ól4Ȟ",
			",Q7钎漡臧n"
		  ],
		  "request_object_signing_alg": "3@¡廜+v,淬Ʋ4Dʧ呩锏緍场",
		  "token_endpoint_auth_signing_alg": "(ưƓǴ罷ǹ~]ea胠"
		},
		"scopes": [
		  "ĩv絹b垇IŕĩǀŻQ'k頂箨J-a稆",
		  "啶#昏Q遐*\\髎bŸ"
		],
		"grantedScopes": [
		  "慂UFƼĮǡ鑻Z"
		],
		"form": {
		  "褾攚ŝlĆ厦駳骪l拁乖¡J¿Ƈ妔": [
			"懧¥ɂĵ~Čyʊ恀c\"Ǌřðȿ/",
			"裢?霃谥vƘ:ƿ/濔Aʉ<",
			"ȭ$奍囀ǅ悷鵱民撲ʓeŘ嬀j¤"
		  ],
		  "诞": [
			"狲N<Cq罉ZPſĝEK郊©l",
			"餚Ǉ/ɷȑ潠[ĝU噤'pX ",
			"Y妶ǵ!ȁu狍ɶȳsčɦƦ诱"
		  ]
		},
		"session": {
		  "Claims": {
			"JTI": "攬林Ñz焁糳¿o>Q鱙翑ȲŻ",
			"Issuer": "锰劝旣樎Ȱ鍌#ȳńƩŴȭ",
			"Subject": "绝TFǊĆw宵ɚeY48珎²",
			"Audience": [
			  "éã越|j¦鲶H股ƲLŋZ-{5£踉4"
			],
			"Nonce": "5^驜Ŗ~ů崧軒q腟u尿",
			"ExpiresAt": "2065-11-30T13:47:03.613000626Z",
			"IssuedAt": "1976-02-22T09:57:20.479850437Z",
			"RequestedAt": "2016-04-13T04:18:53.648949323Z",
			"AuthTime": "2098-07-12T04:38:54.034043015Z",
			"AccessTokenHash": "嫯R",
			"AuthenticationContextClassReference": "¤'+ʣ",
			"AuthenticationMethodsReference": "L&ɽ艄ʬʏ",
			"CodeHash": "ğǫ\\aȊ4ț髄Al",
			"Extra": {
			  "PƢ曰": {
				"ĸŴB岺Ð嫹Sx镯荫ő": [
				  843216989
				],
				"疂ư墫ɓ": {
				  "\\BRë_g\"ʎ啴SƇMǃļ": {
					"ʦ4": false
				  },
				  "鶡萷ɵ啜s攦": null
				}
			  },
			  "曓蓳n匟鯘磹*金爃鶴滱ůĮǐ_c3#": 2520197933
			}
		  },
		  "Headers": {
			"Extra": {
			  "寱ĊƑ÷Ƒ螞费Ďğ~劰û橸ɽ銐ƭ?}": {
				"ȜʁɁ;Bd謺錳4帳ŅǃĊd": {
				  "翢砜Fȏl鐉诳DT=3骜": {
					"ų厷ɁOƪ穋嶿鳈恱va|载ǰɱ汶C": false
				  },
				  "鸨EJ毕懴řĬń戹%c": null
				},
				"室癑勦e骲v0H晦XŘO溪V蔓Ȍ+~ē": [
				  954647573
				]
			  },
			  "麈ƵDǀ\\郂üţ垂": 1572524915
			}
		  },
		  "ExpiresAt": {
			"'=ĸ闒NȢȰ.醋fʜ": "2031-10-18T22:07:34.950803105Z",
			"ɦüHêQ仏1őƖ2Ė暮唍ǞʜƢú4": "2049-05-13T15:27:20.968432454Z"
		  },
		  "Username": "+韁臯氃妪婝rȤ\"h丬鎒ơ娻}ɼƟȥE",
		  "Subject": "龳ǽÙ龦O亾EW莛8嘶×姮c恭企"
		},
		"requestedAudience": [
		  "邖ɐ5檄¬",
		  "Ĭ葜SŦ餧Ĭ倏4ĵ嶼仒篻ɥ闣ʬ橳(ý綃"
		],
		"grantedAudience": [
		  "ʚƟ覣k眐4ĈtC嵽痊w©Ź榨Q|ô",
		  "猊Ia瓕巈環_ɑ彨ƍ蛊ʚ£:設虝2"
		]
	  },
	  "version": "1"
	}`
