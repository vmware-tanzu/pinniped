// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package authorizationcode

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"k8s.io/apimachinery/pkg/api/errors"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/crud"
)

const (
	ErrInvalidAuthorizeRequestType    = constable.Error("authorization request must be of type fosite.AuthorizeRequest")
	ErrInvalidAuthorizeRequestData    = constable.Error("authorization request data must not be nil")
	ErrInvalidAuthorizeRequestVersion = constable.Error("authorization request data has wrong version")

	authorizeCodeStorageVersion = "1"
)

var _ oauth2.AuthorizeCodeStorage = &authorizeCodeStorage{}

type authorizeCodeStorage struct {
	storage crud.Storage
}

type AuthorizeCodeSession struct {
	Active  bool                     `json:"active"`
	Request *fosite.AuthorizeRequest `json:"request"`
	Version string                   `json:"version"`
}

func New(secrets corev1client.SecretInterface) oauth2.AuthorizeCodeStorage {
	return &authorizeCodeStorage{storage: crud.New("authorization-codes", secrets)}
}

func (a *authorizeCodeStorage) CreateAuthorizeCodeSession(ctx context.Context, signature string, requester fosite.Requester) error {
	// this conversion assumes that we do not wrap the default type in any way
	// i.e. we use the default fosite.OAuth2Provider.NewAuthorizeRequest implementation
	// note that because this type is serialized and stored in Kube, we cannot easily change the implementation later
	// TODO hydra uses the fosite.Request struct and ignores the extra fields in fosite.AuthorizeRequest
	request, err := validateAndExtractAuthorizeRequest(requester)
	if err != nil {
		return err
	}

	// TODO hydra stores specific fields from the requester
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

	_, err = a.storage.Create(ctx, signature, &AuthorizeCodeSession{Active: true, Request: request, Version: authorizeCodeStorageVersion})
	return err
}

func (a *authorizeCodeStorage) GetAuthorizeCodeSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	// TODO hydra uses the incoming fosite.Session to provide the type needed to json.Unmarshal their session bytes

	// TODO hydra gets the client from its DB as a concrete type via client ID,
	//  the hydra memory client just validates that the client ID exists

	// TODO hydra uses the sha512.Sum384 hash of signature when using JWT as access token to reduce length

	session, _, err := a.getSession(ctx, signature)

	// we need to always pass both the request and error back
	if session == nil {
		return nil, err
	}

	return session.Request, err
}

func (a *authorizeCodeStorage) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	// TODO write garbage collector for these codes

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
		return nil, "", fosite.ErrNotFound.WithCause(err).WithDebug(err.Error())
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to get authorization code session for %s: %w", signature, err)
	}

	if version := session.Version; version != authorizeCodeStorageVersion {
		return nil, "", fmt.Errorf("%w: authorization code session for %s has version %s instead of %s",
			ErrInvalidAuthorizeRequestVersion, signature, version, authorizeCodeStorageVersion)
	}

	if session.Request == nil {
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
		Request: &fosite.AuthorizeRequest{
			Request: fosite.Request{
				Client:  &fosite.DefaultOpenIDConnectClient{},
				Session: &openid.DefaultSession{},
			},
		},
	}
}

func validateAndExtractAuthorizeRequest(requester fosite.Requester) (*fosite.AuthorizeRequest, error) {
	request, ok1 := requester.(*fosite.AuthorizeRequest)
	if !ok1 {
		return nil, ErrInvalidAuthorizeRequestType
	}
	_, ok2 := request.Client.(*fosite.DefaultOpenIDConnectClient)
	_, ok3 := request.Session.(*openid.DefaultSession)

	valid := ok2 && ok3
	if !valid {
		return nil, ErrInvalidAuthorizeRequestType
	}

	return request, nil
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
		"responseTypes": [
			"¥Îʒ襧.ɕ7崛瀇莒AȒ[ɠ牐7#$ɭ",
			".5ȿEǈ9ûF済(D疻翋膗",
			"螤Yɫüeɯ紤邥翔勋\\RBʒ;-"
		],
		"redirectUri": {
			"Scheme": "ħesƻU赒M喦_ģ",
			"Opaque": "Ġ/_章Ņ缘T蝟Ǌ儱礹燃ɢ",
			"User": {},
			"Host": "ȳ4螘Wo",
			"Path": "}i{",
			"RawPath": "5ǅa丝eF0eė鱊hǒx蔼Q",
			"ForceQuery": true,
			"RawQuery": "熤1bbWV",
			"Fragment": "ȋc剠鏯ɽÿ¸",
			"RawFragment": "qƤ"
		},
		"state": "@n,x竘Şǥ嗾稀'ã击漰怼禝穞梠Ǫs",
		"handledResponseTypes": [
			"m\"e尚鬞ƻɼ抹d誉y鿜Ķ"
		],
		"id": "ō澩ć|3U2Ǜl霨ǦǵpƉ",
		"requestedAt": "1989-11-05T22:02:31.105295894Z",
		"client": {
			"id": "[:c顎疻紵D",
			"client_secret": "mQ==",
			"redirect_uris": [
				"恣S@T嵇ǇV,Æ櫔袆鋹奘菲",
				"ãƻʚ肈ą8O+a駣Ʉɼk瘸'鴵y"
			],
			"grant_types": [
				".湆ê\"唐",
				"曎餄FxD溪躲珫ÈşɜȨû臓嬣\"ǃŤz"
			],
			"response_types": [
				"Ņʘʟ車sʊ儓JǐŪɺǣy|耑ʄ"
			],
			"scopes": [
				"Ą",
				"萙Į(潶饏熞ĝƌĆ1",
				"əȤ4Į筦p煖鵄$睱奐耡q"
			],
			"audience": [
				"Ʃǣ鿫/Ò敫ƤV"
			],
			"public": true,
			"jwks_uri": "ȩđ[嬧鱒Ȁ彆媚杨嶒ĤG",
			"jwks": {
				"keys": [
					{
						"kty": "OKP",
						"crv": "Ed25519",
						"x": "JmA-6KpjzqKu0lq9OiB6ORL4s2UzBFPsE1hm6vESeXM",
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
						"x": "LbRC1_3HEe5o7Japk9jFp3_7Ou7Gi2gpqrVrIi0eLDQ",
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
						"x": "Ovk4DF8Yn3mkULuTqnlGJxFnKGu9EL6Xcf2Nql9lK3c",
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
			"token_endpoint_auth_method": "\u0026(K鵢Kj ŏ9Q韉Ķ%嶑輫ǘ(",
			"request_uris": [
				":",
				"6ě#嫀^xz Ū胧r"
			],
			"request_object_signing_alg": "^¡!犃ĹĐJí¿ō擫ų懫砰¿",
			"token_endpoint_auth_signing_alg": "ƈŮå"
		},
		"scopes": [
			"阃.Ù頀ʌGa皶竇瞍涘¹",
			"ȽŮ切衖庀ŰŒ矠",
			"楓)馻řĝǕ菸Tĕ1伞柲\u003c\"ʗȆ\\雤"
		],
		"grantedScopes": [
			"ơ鮫R嫁ɍUƞ9+u!Ȱ",
			"}Ă岜"
		],
		"form": {
			"旸Ť/Õ薝隧;綡,鼞纂=": [
				"[滮]憀",
				"3\u003eÙœ蓄UK嗤眇疟Țƒ1v¸KĶ"
			]
		},
		"session": {
			"Claims": {
				"JTI": "};Ų斻遟a衪荖舃",
				"Issuer": "芠顋敀拲h蝺$!",
				"Subject": "}j%(=ſ氆]垲莲顇",
				"Audience": [
					"彑V\\廳蟕Țǡ蔯ʠ浵Ī龉磈螖畭5",
					"渇Ȯʕc"
				],
				"Nonce": "Ǖ=rlƆ褡{ǏS",
				"ExpiresAt": "1975-11-17T14:21:34.205609651Z",
				"IssuedAt": "2104-07-03T15:40:03.66710966Z",
				"RequestedAt": "2031-05-18T05:14:19.449350555Z",
				"AuthTime": "2018-01-27T07:55:06.056862114Z",
				"AccessTokenHash": "鹰肁躧",
				"AuthenticationContextClassReference": "}Ɇ",
				"AuthenticationMethodsReference": "DQh:uȣ",
				"CodeHash": "ɘȏıȒ諃龟",
				"Extra": {
					"a": {
						"^i臏f恡ƨ彮": {
							"DĘ敨ýÏʥZq7烱藌\\": null,
							"V": {
								"őŧQĝ微'X焌襱ǭɕņ殥!_n": false
							}
						},
						"Ż猁": [
							1706822246
						]
					},
					"Ò椪)ɫqň2搞Ŀ高摠鲒鿮禗O": 1233332227
				}
			},
			"Headers": {
				"Extra": {
					"?戋璖$9\u0026": {
						"µcɕ餦ÑEǰ哤癨浦浏1R": [
							3761201123
						],
						"頓ć§蚲6rǦ\u003cqċ": {
							"Łʀ§ȏœɽǲ斡冭ȸěaʜD捛?½ʀ+": null,
							"ɒúĲ誠ƉyÖ.峷1藍殙菥趏": {
								"jHȬȆ#)\u003cX": true
							}
						}
					},
					"U": 1354158262
				}
			},
			"ExpiresAt": {
				"\"嘬ȹĹaó剺撱Ȱ": "1985-09-09T04:35:40.533197189Z",
				"ʆ\u003e": "1998-08-07T05:37:11.759718906Z",
				"柏ʒ鴙*鸆偡Ȓ肯Ûx": "2036-12-19T06:36:14.414805124Z"
			},
			"Username": "qmʎaðƠ绗ʢ緦Hū",
			"Subject": "屾Ê窢ɋ鄊qɠ谫ǯǵƕ牀1鞊\\ȹ)"
		},
		"requestedAudience": [
			"鉍商OɄƣ圔,xĪɏV鵅砍"
		],
		"grantedAudience": [
			"C笜嚯\u003cǐšɚĀĥʋ6鉅\\þc涎漄Ɨ腼"
		]
	},
	"version": "1"
}`
