// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package authorizationcode

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/ory/fosite"
	fositeoauth2 "github.com/ory/fosite/handler/oauth2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/federationdomain/clientregistry"
	"go.pinniped.dev/internal/federationdomain/timeouts"
	"go.pinniped.dev/internal/fositestorage"
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
	// Version 6 is when we upgraded fosite in Dec 2023.
	// Version 7 is when OIDCClients were given configurable ID token lifetimes.
	// Version 8 is when GitHubIdentityProvider was added.
	authorizeCodeStorageVersion = "8"
)

var _ fositeoauth2.AuthorizeCodeStorage = &authorizeCodeStorage{}

type authorizeCodeStorage struct {
	storage  crud.Storage
	lifetime timeouts.StorageLifetime
}

type Session struct {
	Active  bool            `json:"active"`
	Request *fosite.Request `json:"request"`
	Version string          `json:"version"`
}

func New(secrets corev1client.SecretInterface, clock func() time.Time, sessionStorageLifetime timeouts.StorageLifetime) fositeoauth2.AuthorizeCodeStorage {
	return &authorizeCodeStorage{storage: crud.New(TypeLabelValue, secrets, clock), lifetime: sessionStorageLifetime}
}

// ReadFromSecret reads the contents of a Secret as a Session.
func ReadFromSecret(secret *corev1.Secret) (*Session, error) {
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

	_, err = a.storage.Create(ctx,
		signature,
		&Session{Active: true, Request: request, Version: authorizeCodeStorageVersion},
		nil,
		nil,
		a.lifetime(requester),
	)
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
		if apierrors.IsConflict(err) {
			return &errSerializationFailureWithCause{cause: err}
		}
		return err
	}

	return nil
}

func (a *authorizeCodeStorage) getSession(ctx context.Context, signature string) (*Session, string, error) {
	session := NewValidEmptyAuthorizeCodeSession()
	rv, err := a.storage.Get(ctx, signature, session)

	if apierrors.IsNotFound(err) {
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
	return stderrors.Is(err, fosite.ErrSerializationFailure)
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
						"x5u": "https://x5u.example.com"
					},
					{
						"kty": "OKP",
						"crv": "Ed25519",
						"x": "1PwKrC4qDe8cabzGTdA0NjuMJhAZAw7Bu7Tj9z2Y4pE",
						"x5u": "https://x5u.example.com"
					},
					{
						"kty": "OKP",
						"crv": "Ed25519",
						"x": "j4b-Vld5buh_2KIpjjaDRJ8OY7l7d6XAumvDtVTT9BI",
						"x5u": "https://x5u.example.com"
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
			"token_endpoint_auth_signing_alg": "ưƓǴ罷ǹ~]ea胠Ĺĩv絹b垇I",
			"IDTokenLifetimeConfiguration": 2593156354696908951
		},
		"scopes": [
			"ǀŻQ'k頂箨J-",
			"銈ɓ"
		],
		"grantedScopes": [
			"#昏Q遐*\\髎bŸ1慂UFƼ",
			"Oǹ冟[ǟ褾攚ŝlĆ",
			"駳骪l拁乖¡J¿Ƈ妔M"
		],
		"form": {
			"¥": [
				"碓ɎǛƍdÚ慂+槰蚪i齥篗裢?霃谥v"
			],
			"囡莒汗狲N": [
				"霋Ɔ輡5ȏ樛ȧ.mĔ櫓Ǩ療",
				"Ǉ/"
			],
			"礐jµ": [
				"A",
				"Jǽȭ$奍囀ǅ悷鵱民撲ʓeŘ嬀",
				"行"
			]
		},
		"session": {
			"fosite": {
				"id_token_claims": {
					"jti": "8",
					"iss": "[ĝU噤'pX ʨ裄@",
					"sub": "!ȁu狍ɶȳsčɦƦ诱ļ攬林Ñ",
					"aud": [
						"ƍ",
						"¿o\u003e"
					],
					"nonce": "ɔ闏À1#锰劝旣樎Ȱ",
					"exp": "2008-03-21T05:57:43.261171532Z",
					"iat": "2080-07-31T09:39:36.259602759Z",
					"rat": "2093-01-01T11:32:44.398071123Z",
					"auth_time": "2088-07-12T21:20:22.8199645Z",
					"at_hash": "鎅ǸÖ绝TFǊĆw宵ɚe",
					"acr": "ùZ蛆鬣a\"ÙǞ0觢Û±¤ǟaȭ_Ǣ",
					"amr": [
						"-{5£踉4"
					],
					"c_hash": "5^驜Ŗ~ů崧軒q腟u尿",
					"ext": {
						"ğ": 1479850437,
						"ǎ^嫯R忑隯ƗƋ*L\u0026": {
							"4鞀腉篓ğǫ\\aȊ4ț髄AlȒ曓蓳n匟": [
								1260036883
							],
							"磹*金爃鶴滱ůĮǐ": {
								"c3#\u0026PƢ曰l騌蘙螤": null,
								"Ð嫹Sx镯荫őł": {
									"鿞ČY\u0026鶡萷ɵ啜s攦Ɩ": true
								}
							}
						}
					}
				},
				"headers": {
					"extra": {
						"Rë_g\"": 573016912,
						"啴SƇMǃļū@$": {
							"i\u0026\u0026Q@Ǥ": {
								"ĊƑ÷Ƒ螞费": null,
								"Ƈ畋rɞ?Ɵ]旎Ȳ濡胉室癑勦e": {
									"9ǍȬ劘$iA砳_": true
								}
							},
							"胬龯,t": [
								1355041984
							]
						}
					}
				},
				"expires_at": {
					"埅ȜʁɁ;Bd謺錳4帳Ņ": "1982-04-18T19:26:28.008651843Z",
					"碼Ǫ": "2028-05-31T03:22:30.23394531Z"
				},
				"username": "鋖颤ōɓɡ Ǽǟ迍阊v\"豑觳翢砜",
				"subject": "ɆƊ#XɗD愌铵ĸYų厷ɁOƪ"
			},
			"custom": {
				"username": "嶿鳈恱va|载ǰɱ汶C]ɲ'=ĸ",
				"upstreamUsername": "ʣ®ǅȪǣǎǔ爣縗ɦüHêQ仏1őƖ2",
				"upstreamGroups": [
					"Ȇ",
					"ǞʜƢú4¶鎰"
				],
				"providerUID": "韁臯氃妪婝rȤ\"h丬鎒ơ娻}ɼƟ",
				"providerName": "闺髉龳ǽÙ龦O亾EW莛8嘶×",
				"providerType": "戙鵮碡ʯiŬŽ非Ĝ眧Ĭ葜SŦ",
				"warnings": [
					"觛ǂ焺nŐǛ3}Ü#",
					"(ý綃ʃʚƟ覣k眐4ĈtC嵽痊w©"
				],
				"oidc": {
					"upstreamRefreshToken": "榨Q|ôɵt毇",
					"upstreamAccessToken": "瓕巈",
					"upstreamSubject": "鉢緋uƴŤȱʀļÂ?",
					"upstreamIssuer": "27就伒犘c钡ɏȫ"
				},
				"ldap": {
					"userDN": "š%OpKȱ藚ɏ¬Ê蒭堜",
					"extraRefreshAttributes": {
						"1飞": "笿0D餹",
						"誮rʨ鷞aŚB碠k9帴ʘ赱ŕ瑹xȢ~": ")藵睋邔\u0026Ű惫蜀Ģ¡圔鎥墀"
					}
				},
				"activedirectory": {
					"userDN": "êĝ",
					"extraRefreshAttributes": {
						"IȽ齤士bEǎ": "跞@)¿,ɭS隑ip偶宾儮猷V麹",
						"ȝƋ鬯犦獢9c5¤.岵": "浛a齙\\蹼偦歛"
					}
				},
				"github": {
					"upstreamAccessToken": " 皦pSǬŝ社Vƅȭǝ*擦28ǅ"
				}
			}
		},
		"requestedAudience": [
			"甍 ć\u003cʘ筫",
			"蛖a³2ʫ承dʬ)ġ,TÀqy_"
		],
		"grantedAudience": [
			"$+溪ŸȢŒų崓ļ憽",
			"姧骦:駝重EȫʆɵʮGɃ"
		]
	},
	"version": "8"
}`
