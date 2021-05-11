module go.pinniped.dev

go 1.14

require (
	cloud.google.com/go v0.60.0 // indirect
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	github.com/coreos/go-oidc/v3 v3.0.0
	github.com/creack/pty v1.1.11
	github.com/davecgh/go-spew v1.1.1
	github.com/go-ldap/ldap/v3 v3.3.0
	github.com/go-logr/logr v0.4.0
	github.com/go-logr/stdr v0.4.0
	github.com/go-openapi/spec v0.20.3
	github.com/gofrs/flock v0.8.0
	github.com/golang/mock v1.5.0
	github.com/google/go-cmp v0.5.5
	github.com/google/gofuzz v1.2.0
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/websocket v1.4.2
	github.com/oleiade/reflections v1.0.1 // indirect
	github.com/onsi/ginkgo v1.13.0 // indirect
	github.com/ory/fosite v0.39.0
	github.com/pkg/browser v0.0.0-20201207095918-0426ae3fba23
	github.com/pkg/errors v0.9.1
	github.com/sclevine/agouti v3.0.0+incompatible
	github.com/sclevine/spec v1.4.0
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a
	golang.org/x/term v0.0.0-20210220032956-6a3ed077a48d
	gopkg.in/square/go-jose.v2 v2.5.1
	k8s.io/api v0.21.0
	k8s.io/apimachinery v0.21.0
	k8s.io/apiserver v0.21.0
	k8s.io/client-go v0.21.0
	k8s.io/component-base v0.21.0
	k8s.io/gengo v0.0.0-20201214224949-b6c5ce23f027
	k8s.io/klog/v2 v2.8.0
	k8s.io/kube-aggregator v0.21.0
	k8s.io/kube-openapi v0.0.0-20210305001622-591a79e4bda7
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920
	sigs.k8s.io/yaml v1.2.0
)

// Workaround a broken module version (see https://github.com/oleiade/reflections/issues/14).
// We need this until none of our deps tries to pull in v1.0.0, otherwise some tools like
// Dependabot will fail on our module.
replace github.com/oleiade/reflections v1.0.0 => github.com/oleiade/reflections v1.0.1

// We were never vulnerable to CVE-2020-26160 but this avoids future issues
// This fork is not particularly better though:
// https://github.com/form3tech-oss/jwt-go/issues/7
// We use the SHA of github.com/form3tech-oss/jwt-go@v3.2.2 to get around "used for two different module paths"
// https://golang.org/issues/26904
replace github.com/dgrijalva/jwt-go v3.2.0+incompatible => github.com/form3tech-oss/jwt-go v0.0.0-20200915135329-9162a5abdbc0
