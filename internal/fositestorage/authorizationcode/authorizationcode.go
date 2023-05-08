// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package authorizationcode

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/fositestorage"
	"go.pinniped.dev/internal/oidc/clientregistry"
	"go.pinniped.dev/internal/psession"
)

const (
	TypeLabelValue = "authcode"

	ErrInvalidAuthorizeRequestData    = constable.Error("authorization request data must be present")
	ErrInvalidAuthorizeRequestVersion = constable.Error("authorization request data has wrong version")

	// Version 1 was the initial release of storage.
	// Version 2 is when we switched to storing psession.PinnipedSession inside the fosite request.
	// Version 3 is when we added the Username field to the psession.CustomSessionData.
	// Version 4 is when fosite added json tags to their openid.DefaultSession struct.
	// Version 5 is when we added the UpstreamUsername and UpstreamGroups fields to psession.CustomSessionData.
	authorizeCodeStorageVersion = "5"
)

var _ oauth2.AuthorizeCodeStorage = &authorizeCodeStorage{}

type authorizeCodeStorage struct {
	storage crud.Storage
}

type Session struct {
	Active  bool            `json:"active"`
	Request *fosite.Request `json:"request"`
	Version string          `json:"version"`
}

func New(secrets corev1client.SecretInterface, clock func() time.Time, sessionStorageLifetime time.Duration) oauth2.AuthorizeCodeStorage {
	return &authorizeCodeStorage{storage: crud.New(TypeLabelValue, secrets, clock, sessionStorageLifetime)}
}

// ReadFromSecret reads the contents of a Secret as a Session.
func ReadFromSecret(secret *v1.Secret) (*Session, error) {
	session := NewValidEmptyAuthorizeCodeSession()
	err := crud.FromSecret(TypeLabelValue, secret, session)
	if err != nil {
		return nil, err
	}
	if session.Version != authorizeCodeStorageVersion {
		return nil, fmt.Errorf("%w: authorization code session has version %s instead of %s",
			ErrInvalidAuthorizeRequestVersion, session.Version, authorizeCodeStorageVersion)
	}
	if session.Request.ID == "" {
		return nil, fmt.Errorf("malformed authorization code session: %w", ErrInvalidAuthorizeRequestData)
	}
	return session, nil
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

	_, err = a.storage.Create(ctx, signature, &Session{Active: true, Request: request, Version: authorizeCodeStorageVersion}, nil, nil)
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

func (a *authorizeCodeStorage) getSession(ctx context.Context, signature string) (*Session, string, error) {
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

func NewValidEmptyAuthorizeCodeSession() *Session {
	return &Session{
		Request: &fosite.Request{
			Client:  &clientregistry.Client{},
			Session: &psession.PinnipedSession{},
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
			"rotated_secrets": [
				"Bno=",
				"0j8=",
				"1c4="
			],
			"redirect_uris": [
				"ʊXĝ",
				"Ƿ"
			],
			"grant_types": [
				"祩d",
				"zŇZ",
				"優蒼ĊɌț訫ǄǽeʀO2ƚ\u0026N"
			],
			"response_types": [
				"唐W6ɻ橩斚薛ɑƐ"
			],
			"scopes": [
				"w",
				"ǔŭe[u@阽羂ŷ-Ĵ½輢OÅ濲喾H"
			],
			"audience": [
				"G螩歐湡ƙı唡ɸğƎ\u0026胢輢Ƈĵƚ"
			],
			"public": false,
			"jwks_uri": "潌țjA9;焋Ēƕ",
			"jwks": {
				"keys": [
					{
						"kty": "OKP",
						"crv": "Ed25519",
						"x": "LHMZ29A64WecPQSLotS8hfZ2mae0SR17CtPdnMDP7ZI",
						"x5u": {
							"Scheme": "",
							"Opaque": "",
							"User": null,
							"Host": "",
							"Path": "",
							"RawPath": "",
							"OmitHost": false,
							"ForceQuery": false,
							"RawQuery": "",
							"Fragment": "",
							"RawFragment": ""
						}
					},
					{
						"kty": "OKP",
						"crv": "Ed25519",
						"x": "1PwKrC4qDe8cabzGTdA0NjuMJhAZAw7Bu7Tj9z2Y4pE",
						"x5u": {
							"Scheme": "",
							"Opaque": "",
							"User": null,
							"Host": "",
							"Path": "",
							"RawPath": "",
							"OmitHost": false,
							"ForceQuery": false,
							"RawQuery": "",
							"Fragment": "",
							"RawFragment": ""
						}
					},
					{
						"kty": "OKP",
						"crv": "Ed25519",
						"x": "j4b-Vld5buh_2KIpjjaDRJ8OY7l7d6XAumvDtVTT9BI",
						"x5u": {
							"Scheme": "",
							"Opaque": "",
							"User": null,
							"Host": "",
							"Path": "",
							"RawPath": "",
							"OmitHost": false,
							"ForceQuery": false,
							"RawQuery": "",
							"Fragment": "",
							"RawFragment": ""
						}
					}
				]
			},
			"token_endpoint_auth_method": "趀Ȁ;hYGe天蹗ĽǙ澅j翕q骽",
			"request_uris": [
				"Ǐ蛓ȿ,JwwƐ\u003c涵ØƉKĵ",
				"Ȟú",
				"Q7钎漡臧n栀,i"
			],
			"request_object_signing_alg": "廜+v,淬Ʋ4Dʧ呩锏緍场脋",
			"token_endpoint_auth_signing_alg": "ưƓǴ罷ǹ~]ea胠Ĺĩv絹b垇I"
		},
		"scopes": [
			"ĩǀŻQ'k頂箨J-a",
			"ɓ啶#昏Q遐*\\髎bŸ1慂U"
		],
		"grantedScopes": [
			"ƼĮǡ鑻Z¥篚h°ʣ£ǖ%\"砬ʍ"
		],
		"form": {
			"¡": [
				"Ła卦牟懧¥ɂĵ",
				"ɎǛƍdÚ慂+槰蚪i齥篗裢?霃谥vƘ:",
				"/濔Aʉ\u003cS獾蔀OƭUǦ"
			],
			"民撲ʓeŘ嬀j¤囡莒汗狲N\u003cCq": [
				"5ȏ樛ȧ.mĔ櫓Ǩ療騃Ǐ}ɟ",
				"潠[ĝU噤'",
				"ŁȗɉY妶ǵ!ȁ"
			],
			"褰ʎɰ癟VĎĢ婄磫绒u妔隤ʑƍš駎竪": [
				"鱙翑ȲŻ麤ã桒嘞\\摗Ǘū稖咾鎅ǸÖ"
			]
		},
		"session": {
			"fosite": {
				"id_token_claims": {
					"jti": "褗6巽ēđų蓼tùZ蛆鬣a\"ÙǞ0觢",
					"iss": "j¦鲶H股ƲLŋZ-{",
					"sub": "ehpƧ蓟",
					"aud": [
						"驜Ŗ~ů崧軒q腟u尿宲!"
					],
					"nonce": "ǎ^嫯R忑隯ƗƋ*L\u0026",
					"exp": "1989-06-02T14:40:29.613836765Z",
					"iat": "2052-03-26T02:39:27.882495556Z",
					"rat": "2038-04-06T10:46:24.698586972Z",
					"auth_time": "2003-01-05T11:30:18.206004879Z",
					"at_hash": "ğǫ\\aȊ4ț髄Al",
					"acr": "曓蓳n匟鯘磹*金爃鶴滱ůĮǐ_c3#",
					"amr": [
						"装ƹýĸŴB岺Ð嫹Sx镯荫őł疂ư墫"
					],
					"c_hash": "\u0026鶡",
					"ext": {
						"rǓ\\BRë_g\"ʎ啴SƇMǃļū": {
							"4撎胬龯,t猟i\u0026\u0026Q@ǤǟǗ": [
								1239190737
							],
							"飘ȱF?Ƈ畋": {
								"劰û橸ɽ銐ƭ?}HƟ玈鳚": null,
								"骲v0H晦XŘO溪V蔓Ȍ+~ē埅Ȝ": {
									"4Ǟ": false
								}
							}
						},
						"鑳绪": 2738428764
					}
				},
				"headers": {
					"extra": {
						"d謺錳4帳ŅǃĊ": 663773398,
						"Ř鸨EJ": {
							"Ǽǟ迍阊v\"豑觳翢砜": [
								995342744
							],
							"ȏl鐉诳DT=3骜Ǹ": {
								"厷ɁOƪ穋嶿鳈恱va|载ǰɱ汶C]ɲ": null,
								"荤Ý呐ʣ®ǅȪǣǎǔ爣縗ɦü": {
									"H :靥湤庤毩fɤȆʪ融ƆuŤn": true
								}
							}
						}
					}
				},
				"expires_at": {
					"韁臯氃妪婝rȤ\"h丬鎒ơ娻}ɼƟ": "1970-04-27T04:31:30.902468229Z"
				},
				"username": "髉龳ǽÙ",
				"subject": "\u0026¥潝邎Ȗ莅ŝǔ盕戙鵮碡ʯiŬŽ"
			},
			"custom": {
				"username": "Ĝ眧Ĭ",
				"providerUID": "ŉ2ƋŢ觛ǂ焺nŐǛ",
				"providerName": "ɥ闣ʬ橳(ý綃ʃʚƟ覣k眐4",
				"providerType": "ȣ掘ʃƸ澺淗a紽ǒ|鰽",
				"warnings": [
					"t毇妬\u003e6鉢緋uƴŤȱʀļÂ",
					"虝27就伒犘c钡ɏȫ齁š"
				],
				"oidc": {
					"upstreamRefreshToken": "OpKȱ藚ɏ¬Ê蒭堜]ȗ韚ʫ繕ȫ碰+ʫ",
					"upstreamAccessToken": "k9帴",
					"upstreamSubject": "磊ůď逳鞪?3)藵睋邔\u0026Ű惫蜀Ģ",
					"upstreamIssuer": "4İ"
				},
				"ldap": {
					"userDN": "×",
					"extraRefreshAttributes": {
						"ʥ笿0D": "s"
					}
				},
				"activedirectory": {
					"userDN": "ĝ",
					"extraRefreshAttributes": {
						"IȽ齤士bEǎ": "跞@)¿,ɭS隑ip偶宾儮猷V麹",
						"ȝƋ鬯犦獢9c5¤.岵": "浛a齙\\蹼偦歛"
					}
				}
			}
		},
		"requestedAudience": [
			" 皦pSǬŝ社Vƅȭǝ*擦28ǅ",
			"vư"
		],
		"grantedAudience": [
			"置b",
			"筫MN\u0026錝D肁Ŷɽ蔒PR}Ųʓl{"
		]
	},
	"version": "4"
}`
