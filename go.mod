module go.pinniped.dev

go 1.16

require (
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	github.com/coreos/go-oidc/v3 v3.0.0
	github.com/creack/pty v1.1.14
	github.com/davecgh/go-spew v1.1.1
	github.com/go-ldap/ldap/v3 v3.3.0
	github.com/go-logr/logr v0.4.0
	github.com/go-logr/stdr v0.4.0
	github.com/go-openapi/spec v0.20.3 // indirect
	github.com/gofrs/flock v0.8.1
	github.com/golang/mock v1.6.0
	github.com/google/go-cmp v0.5.6
	github.com/google/gofuzz v1.2.0
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/websocket v1.4.2
	github.com/ory/fosite v0.40.2
	github.com/pkg/browser v0.0.0-20210115035449-ce105d075bb4
	github.com/pkg/errors v0.9.1
	github.com/sclevine/agouti v3.0.0+incompatible
	github.com/sclevine/spec v1.4.0
	github.com/spf13/cobra v1.2.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/tdewolff/minify/v2 v2.9.20
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/net v0.0.0-20210520170846-37e1c6afe023
	golang.org/x/oauth2 v0.0.0-20210402161424-2e8d93401602
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/term v0.0.0-20210503060354-a79de5458b56
	gopkg.in/square/go-jose.v2 v2.6.0
	k8s.io/api v0.22.0
	k8s.io/apimachinery v0.22.0
	k8s.io/apiserver v0.21.3
	k8s.io/client-go v0.21.3
	k8s.io/component-base v0.21.3
	k8s.io/gengo v0.0.0-20210203185629-de9496dff47b
	k8s.io/klog/v2 v2.10.0
	k8s.io/kube-aggregator v0.21.3
	k8s.io/utils v0.0.0-20210521133846-da695404a2bc
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

// Pin gRPC back to v1.29.1 (the version required by Kubernetes), but also override a module that's only used in some tests.
// This is required because sometime after v1.29.1, they moved this package into a separate module.
replace (
	google.golang.org/grpc => google.golang.org/grpc v1.29.1
	google.golang.org/grpc/examples => ./hack/dependencyhacks/grpcexamples/
)
