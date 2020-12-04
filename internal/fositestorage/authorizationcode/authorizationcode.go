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

func New(secrets corev1client.SecretInterface) oauth2.AuthorizeCodeStorage {
	return &authorizeCodeStorage{storage: crud.New(TypeLabelValue, secrets)}
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
		return nil, "", fosite.ErrNotFound.WithCause(err).WithDebug(err.Error())
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
		"id": "嫎l蟲aƖ啘艿",
		"requestedAt": "2082-11-10T18:36:11.627253638Z",
		"client": {
			"id": "!ſɄĈp[述齛ʘUȻ.5ȿE",
			"client_secret": "UQ==",
			"redirect_uris": [
				"ǣ珑 ʑ飶畛Ȳ螤Yɫüeɯ紤邥翔勋\\",
				"Bʒ;",
				"鿃攴Ųęʍ鎾ʦ©cÏN,Ġ/_"
			],
			"grant_types": [
				"憉sHĒ尥窘挼Ŀŉ"
			],
			"response_types": [
				"4",
				"ʄÔ@}i{絧遗Ū^ȝĸ谋Vʋ鱴閇T"
			],
			"scopes": [
				"R鴝順諲ŮŚ节ȭŀȋc剠鏯ɽÿ¸"
			],
			"audience": [
				"Ƥ"
			],
			"public": true,
			"jwks_uri": "BA瘪囷ɫCʄɢ雐譄uée'",
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
			"token_endpoint_auth_method": "ŚǗƳȕ暭Q0ņP羾,塐",
			"request_uris": [
				"ǉ翻LH^俤µǲɹ@©|\u003eɃ",
				"[:c顎疻紵D"
			],
			"request_object_signing_alg": "m1Ì恣S@T嵇ǇV,Æ櫔袆鋹奘",
			"token_endpoint_auth_signing_alg": "Fãƻʚ肈ą8O+a駣"
		},
		"scopes": [
			"ɼk瘸'鴵yſǮŁ±\u003eFA曎餄FxD溪",
			"綻N镪p赌h%桙dĽ"
		],
		"grantedScopes": [
			"癗E]Ņʘʟ車s"
		],
		"form": {
			"蹬器ķ8ŷ萒寎廭#疶昄Ą-Ƃƞ轵": [
				"熞ĝƌĆ1ȇyǴ濎=Tʉȼʁŀ\u003c",
				"耡q戨稞R÷mȵg釽[ƞ@",
				"đ[嬧鱒Ȁ彆媚杨嶒ĤGÀ吧Lŷ"
			],
			"餟": [
				"蒍z\u0026(K鵢Kj ŏ9Q韉Ķ%",
				"輫ǘ(¨Ƞ亱6ě#嫀^xz ",
				"@耢ɝ^¡!犃ĹĐJí¿ō擫"
			]
		},
		"session": {
			"Claims": {
				"JTI": "懫砰¿C筽娴ƓaPu镈賆ŗɰ",
				"Issuer": "皶竇瞍涘¹焕iǢǽɽĺŧ",
				"Subject": "矠M6ɡǜg炾ʙ$%o6肿Ȫ",
				"Audience": [
					"ƌÙ鯆GQơ鮫R嫁ɍUƞ9+u!Ȱ踾$"
				],
				"Nonce": "us旸Ť/Õ薝隧;綡,鼞",
				"ExpiresAt": "2065-11-30T13:47:03.613000626Z",
				"IssuedAt": "1976-02-22T09:57:20.479850437Z",
				"RequestedAt": "2016-04-13T04:18:53.648949323Z",
				"AuthTime": "2098-07-12T04:38:54.034043015Z",
				"AccessTokenHash": "滮]",
				"AuthenticationContextClassReference": "°3\u003eÙ",
				"AuthenticationMethodsReference": "k?µ鱔ǤÂ",
				"CodeHash": "Țƒ1v¸KĶ跭};",
				"Extra": {
					"=ſ氆": {
						"Ƿī,廖ʡ彑V\\廳蟕Ț": [
							843216989
						],
						"蔯ʠ浵Ī": {
							"H\"nǕ=rlƆ褡{ǏSȳŅ": {
								"Žg": false
							},
							"枱鰧ɛ鸁A渇": null
						}
					},
					"斻遟a衪荖舃9闄岈锘肺ńʥƕU}j%": 2520197933
				}
			},
			"Headers": {
				"Extra": {
					"熒ɘȏıȒ諃龟ŴŠ'耐Ƭ扵ƹ玄ɕwL": {
						"ýÏʥZq7烱藌\\捀¿őŧQ": {
							"微'X焌襱ǭɕņ殥!_": null,
							"荇届UȚ?戋璖$9\u00269舋": {
								"ɕ餦ÑEǰ哤癨浦浏1Rk頓ć§蚲6": true
							}
						},
						"鲒鿮禗O暒aJP鐜?ĮV嫎h譭ȉ]DĘ": [
							954647573
						]
					},
					"皩Ƭ}Ɇ.雬Ɨ´唁": 1572524915
				}
			},
			"ExpiresAt": {
				"\u003cqċ譈8ŪɎP绿MÅ": "2031-10-18T22:07:34.950803105Z",
				"ȸěaʜD捛?½ʀ+Ċ偢镳ʬÍɷȓ\u003c": "2049-05-13T15:27:20.968432454Z"
			},
			"Username": "1藍殙菥趏酱Nʎ\u0026^横懋ƶ峦Fïȫƅw",
			"Subject": "檾ĩĆ爨4犹|v炩f柏ʒ鴙*鸆偡"
		},
		"requestedAudience": [
			"肯Ûx穞Ƀ",
			"ź蕴3ǐ薝Ƅ腲=ʐ诂鱰屾Ê窢ɋ鄊qɠ谫"
		],
		"grantedAudience": [
			"ǵƕ牀1鞊\\ȹ)}鉍商OɄƣ圔,xĪ",
			"悾xn冏裻摼0Ʈ蚵Ȼ塕»£#稏扟X"
		]
	},
	"version": "1"
}`
