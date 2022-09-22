# Notes for story acceptance for the dynamic clients feature

Rather than writing a webapp to manually test the dynamic client features during user story acceptance,
we can simulate the requests that a webapp would make to the Supervisor using the commands shown below.
The commands below the happy path for a fully-capable OIDCClient which is allowed to use all supported
grant types and scopes. These commands can be adjusted to test other scenarios of interest.

## Deploy and configure a basic Supervisor locally

We can use the developer hack scripts to deploy a working Supervisor on a local Kind cluster.
These clusters have no ingress, so we use Kind's port mapping feature to expose a web proxy outside
the cluster. The proxy can then be used to access the Supervisor. In this setup, the Supervisor's CA
is not trusted by the web browser, however, the curl commands can trust the CA cert by using the `--cacert` flag.

```shell
./hack/prepare-for-integration-tests.sh -c
source /tmp/integration-test-env
# We'll use LDAP so we can login in via curl commands through the Supervisor.
./hack/prepare-supervisor-on-kind.sh --ldap --flow browser_authcode
```

Alternatively, the Supervisor could be installed into a cluster in a more production-like way, with ingress,
a DNS entry, and TLS certs. In this case, the proxy env vars used below would not be needed, and the issuer string
would be adjusted to match the Supervisor's ingress DNS hostname.

## Create an OIDCClient

```shell
cat <<EOF | kubectl apply -f -
apiVersion: config.supervisor.pinniped.dev/v1alpha1
kind: OIDCClient
metadata:
  # name must have client.oauth.pinniped.dev- prefix
  name: client.oauth.pinniped.dev-my-webapp-client
  namespace: supervisor # must be in the same namespace as the Supervisor
spec:
  allowedRedirectURIs:
    - https://webapp.example.com/callback
  allowedGrantTypes:
    - authorization_code
    - refresh_token
    - urn:ietf:params:oauth:grant-type:token-exchange
  allowedScopes:
    - openid
    - offline_access
    - pinniped:request-audience
    - username
    - groups
EOF
```

Get the OIDCClient to check its status:
```shell
kubectl get oidcclient -n supervisor client.oauth.pinniped.dev-my-webapp-client -o yaml
```

Create a client secret for the OIDCClient:

```shell
cat <<EOF | kubectl create -o yaml -f -
apiVersion: clientsecret.supervisor.pinniped.dev/v1alpha1
kind: OIDCClientSecretRequest
metadata:
  name: client.oauth.pinniped.dev-my-webapp-client # the name of the OIDCClient
  namespace: supervisor # the namespace of the OIDCClient
spec:
  generateNewSecret: true
EOF
```

Example response:

```yaml
apiVersion: clientsecret.supervisor.pinniped.dev/v1alpha1
kind: OIDCClientSecretRequest
metadata:
  creationTimestamp: null
spec:
  generateNewSecret: false
  revokeOldSecrets: false
status:
  generatedSecret: 0cc65d46fb5c0fb80123b28bd8093ae0e61e568b6c35cbca82941dcaa8c67b5b
  totalClientSecrets: 1
```

Make a note of the `generatedSecret` value. It will never be shown again.

## Make an authorization request

The OIDC authcode flow always starts with an authorization request. A webapp would redirect the user's browser
to make this request in a browser. For story acceptance, this request could also be made in a web browser by typing
the full URL with params into the browser's address bar, although here we'll show how to use curl to ensure that we
are documenting the exact requirements of the authorization request.

Authorization parameter notes:
- Authorization requests must use PKCE. For manual testing, these sample values can be used. For production use,
  each authorization request must have a new PKCE value computed for that request.
  - Example code challenge: vTu6b5Jm2hpi1vjRJw7HB820EYNq7AFT1IHDLBQMc3Q
  - Example code verifier: UDABWPiROQh0nfhGzd_7OetrEJZZ7S-Z_H8_ZLB2i8Yc2wix
- Nonce values should also be unique per authorization request in production use.
- State values are optional and will be passed back in the authcode callback if provided.

```shell
PARAMS='?response_type=code'\
'&client_id=client.oauth.pinniped.dev-my-webapp-client'\
'&code_challenge=vTu6b5Jm2hpi1vjRJw7HB820EYNq7AFT1IHDLBQMc3Q'\
'&code_challenge_method=S256'\
'&nonce=9902045656a1c29b95515f7f45b40773'\
'&redirect_uri=https%3A%2F%2Fwebapp.example.com%2Fcallback'\
'&scope=openid+offline_access+username+groups+pinniped%3Arequest-audience'\
'&state=cfcd3a3e72774bee1e748e6bf4a70f5c'

https_proxy="http://127.0.0.1:12346" no_proxy="127.0.0.1" \
  curl -vfLsS --cookie-jar cookies.txt --cacert root_ca.crt \
  "https://pinniped-supervisor-clusterip.supervisor.svc.cluster.local/some/path/oauth2/authorize$PARAMS"
```

When successful, this should redirect to the Supervisor's LDAP login page and return its HTML.
The resulting HTML form will include a hidden param called `state`.
Make a note of its value for the next step.

The LDAP login page's form can be submitted with:

```shell
STATE='COPY_PASTE_HIDDEN_STATE_PARAM_FROM_PREVIOUS_CURL_RESULT_HERE'

https_proxy="http://127.0.0.1:12346" no_proxy="127.0.0.1" \
  curl -vfsS --cookie cookies.txt --cacert root_ca.crt \
  "https://pinniped-supervisor-clusterip.supervisor.svc.cluster.local/some/path/login" \
  --form-string "username=$PINNIPED_TEST_LDAP_USER_CN" \
  --form-string "password=$PINNIPED_TEST_LDAP_USER_PASSWORD" \
  --form-string "state=$STATE"
```

When successful, this should result in an HTTP 302 or 303 redirect response. The `location` header should look something like
`https://webapp.example.com/callback?code=pin_ac_oq7m9z...wuzQ&scope=openid+offline_access+pinniped%3Arequest-audience+username+groups&state=cfcd3a3e72774bee1e748e6bf4a70f5c`
which includes the authcode as the `code` param. Make a note of its value for the next step.

## Make a token request to exchange the authcode obtained in the previous step

The authcode callback would be handled by the webapp's backend. The backend code would then use the authcode
to make a token request to the Supervisor. This would happen as a backend request, so the user's browser would not be
involved.

```shell
CODE='COPY_AUTHCODE_FROM_PREVIOUS_CURL_RESULT_HERE'
CLIENT_SECRET='COPY_CLIENT_SECRET_HERE'

https_proxy="http://127.0.0.1:12346" no_proxy="127.0.0.1" \
  curl -vfsS --cacert root_ca.crt \
  "https://pinniped-supervisor-clusterip.supervisor.svc.cluster.local/some/path/oauth2/token" \
  --form-string "grant_type=authorization_code" \
  --form-string "code=$CODE" \
  --form-string "redirect_uri=https://webapp.example.com/callback" \
  --form-string "code_verifier=UDABWPiROQh0nfhGzd_7OetrEJZZ7S-Z_H8_ZLB2i8Yc2wix" \
  -u "client.oauth.pinniped.dev-my-webapp-client:$CLIENT_SECRET"
```

When successful, this should return some JSON which includes the Supervisor-issued tokens.
The ID token can be decoded for inspection (e.g. using https://jwt.io).
Make a note of the access token and the refresh token for the next steps.

## Make a request for a cluster-scoped ID token

If the webapp wanted to access a Kubernetes cluster on behalf of the end user, it would need to make
an additional request (per cluster) to get a cluster-scoped ID token.

```shell
ACCESS='COPY_ACCESS_TOKEN_FROM_PREVIOUS_CURL_RESULT_HERE'

https_proxy="http://127.0.0.1:12346" no_proxy="127.0.0.1" \
  curl -vfsS --cacert root_ca.crt \
  "https://pinniped-supervisor-clusterip.supervisor.svc.cluster.local/some/path/oauth2/token" \
  --form-string "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --form-string "audience=my-workload-cluster-audience-name" \
  --form-string "subject_token=$ACCESS" \
  --form-string "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --form-string "requested_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -u "client.oauth.pinniped.dev-my-webapp-client:$CLIENT_SECRET"
```

If successful, this should return some JSON with a new cluster-scoped ID token in the response.

## Make a refresh request

The ID and access tokens are very short-lived, so the backend of the webapp should refresh them as needed.

```shell
REFRESH='COPY_REFRESH_TOKEN_FROM_PREVIOUS_CURL_RESULT_HERE'

https_proxy="http://127.0.0.1:12346" no_proxy="127.0.0.1" \
  curl -vfsS --cacert root_ca.crt \
  "https://pinniped-supervisor-clusterip.supervisor.svc.cluster.local/some/path/oauth2/token" \
  --form-string "grant_type=refresh_token" \
  --form-string "refresh_token=$REFRESH" \
  -u "client.oauth.pinniped.dev-my-webapp-client:$CLIENT_SECRET"
```

When successful, this should return some JSON which includes the new Supervisor-issued tokens.
The old refresh token is revoked and the next refresh request must use the newest refresh token.
