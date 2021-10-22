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
	authorizeCodeStorageVersion = "2"
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
			"redirect_uris": [
				"ǖ枭kʍ切厦ȳ箦;¥ʊXĝ奨誷傥祩d",
				"zŇZ",
				"優蒼ĊɌț訫ǄǽeʀO2ƚ\u0026N"
			],
			"grant_types": [
				"唐W6ɻ橩斚薛ɑƐ"
			],
			"response_types": [
				"w",
				"ǔŭe[u@阽羂ŷ-Ĵ½輢OÅ濲喾H"
			],
			"scopes": [
				"G螩歐湡ƙı唡ɸğƎ\u0026胢輢Ƈĵƚ"
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
			"token_endpoint_auth_method": "ƿʥǟȒ伉\u003cx¹T鼓c吏",
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
				"裢?霃谥vƘ:ƿ/濔Aʉ\u003c",
				"ȭ$奍囀ǅ悷鵱民撲ʓeŘ嬀j¤"
			],
			"诞": [
				"狲N\u003cCq罉ZPſĝEK郊©l",
				"餚Ǉ/ɷȑ潠[ĝU噤'pX ",
				"Y妶ǵ!ȁu狍ɶȳsčɦƦ诱"
			]
		},
		"session": {
			"fosite": {
				"Claims": {
					"JTI": "u妔隤ʑƍš駎竪0ɔ闏À1",
					"Issuer": "麤ã桒嘞\\摗Ǘū稖咾鎅ǸÖ绝TF",
					"Subject": "巽ēđų蓼tùZ蛆鬣a\"ÙǞ0觢Û±",
					"Audience": [
						"H股ƲL",
						"肟v\u0026đehpƧ",
						"5^驜Ŗ~ů崧軒q腟u尿"
					],
					"Nonce": "ğ",
					"ExpiresAt": "2016-11-22T21:33:58.460521133Z",
					"IssuedAt": "1990-07-25T23:42:07.055978334Z",
					"RequestedAt": "1971-01-30T00:23:36.377684025Z",
					"AuthTime": "2088-11-09T12:09:14.051840239Z",
					"AccessTokenHash": "蕖¤'+ʣȍ瓁U4鞀",
					"AuthenticationContextClassReference": "ʏÑęN\u003c_z",
					"AuthenticationMethodsReference": "ț髄A",
					"CodeHash": "4磔_袻vÓG-壧丵礴鋈k蟵pAɂʅ",
					"Extra": {
						"#\u0026PƢ曰l騌蘙螤\\阏Đ镴Ƥm蔻ǭ\\鿞": 1677215584,
						"Y\u0026鶡萷ɵ啜s攦Ɩïdnǔ": {
							",t猟i\u0026\u0026Q@ǤǟǗǪ飘ȱF?Ƈ": {
								"~劰û橸ɽ銐ƭ?}H": null,
								"癑勦e骲v0H晦XŘO溪V蔓": {
									"碼Ǫ": false
								}
							},
							"钻煐ɨəÅDČ{Ȩʦ4撎": [
								3684968178
							]
						}
					}
				},
				"Headers": {
					"Extra": {
						"ĊdŘ鸨EJ毕懴řĬń戹": {
							"诳DT=3骜Ǹ,": {
								"\u003e": {
									"ǰ": false
								},
								"ɁOƪ穋嶿鳈恱va": null
							},
							"豑觳翢砜Fȏl": [
								927958776
							]
						},
						"埅ȜʁɁ;Bd謺錳4帳Ņ": 388005986
					}
				},
				"ExpiresAt": {
					"C]ɲ'=ĸ闒NȢȰ.醋": "1970-07-19T18:03:29.902062193Z",
					"fɤȆʪ融ƆuŤn": "2064-01-24T20:34:16.593152073Z",
					"爣縗ɦüHêQ仏1ő": "2102-03-17T06:24:40.256846902Z"
				},
				"Username": "韁臯氃妪婝rȤ\"h丬鎒ơ娻}ɼƟ",
				"Subject": "闺髉龳ǽÙ龦O亾EW莛8嘶×"
			},
			"custom": {
				"providerUID": "鵮碡ʯiŬŽ非Ĝ眧Ĭ葜SŦ餧Ĭ倏4",
				"providerName": "nŐǛ3",
				"providerType": "闣ʬ橳(ý綃ʃʚƟ覣k眐4Ĉt",
				"oidc": {
					"upstreamRefreshToken": "嵽痊w©Ź榨Q|ôɵt毇妬"
				},
				"ldap": {
					"userDN": "6鉢緋uƴŤȱʀļÂ?墖\u003cƬb獭潜Ʃ饾"
				},
				"activedirectory": {
					"userDN": "|鬌R蜚蠣麹概÷驣7Ʀ澉1æɽ誮rʨ鷞"
				}
			}
		},
		"requestedAudience": [
			"ŚB碠k9"
		],
		"grantedAudience": [
			"ʘ赱",
			"ď逳鞪?3)藵睋邔\u0026Ű惫蜀Ģ¡圔",
			"墀jMʥ"
		]
	},
	"version": "2"
}`
