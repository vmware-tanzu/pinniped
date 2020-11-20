module go.pinniped.dev

go 1.14

require (
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/davecgh/go-spew v1.1.1
	github.com/ghodss/yaml v1.0.0
	github.com/go-logr/logr v0.2.1
	github.com/go-logr/stdr v0.2.0
	github.com/gofrs/flock v0.8.0
	github.com/golang/mock v1.4.4
	github.com/golangci/golangci-lint v1.31.0
	github.com/google/go-cmp v0.5.2
	github.com/google/gofuzz v1.1.0
	github.com/gorilla/securecookie v1.1.1
	github.com/ory/fosite v0.35.1
	github.com/pkg/browser v0.0.0-20180916011732-0a3d74bf9ce4
	github.com/sclevine/agouti v3.0.0+incompatible
	github.com/sclevine/spec v1.4.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.6.1
	go.pinniped.dev/generated/1.19/apis v0.0.0-00010101000000-000000000000
	go.pinniped.dev/generated/1.19/client v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.0.0-20200709230013-948cd5f35899
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	gopkg.in/square/go-jose.v2 v2.5.1
	k8s.io/api v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/apiserver v0.19.2
	k8s.io/client-go v0.19.2
	k8s.io/component-base v0.19.2
	k8s.io/klog/v2 v2.3.0
	k8s.io/kube-aggregator v0.19.2
	k8s.io/utils v0.0.0-20200729134348-d5654de09c73
	sigs.k8s.io/yaml v1.2.0
)

replace (
	go.pinniped.dev/generated/1.19/apis => ./generated/1.19/apis
	go.pinniped.dev/generated/1.19/client => ./generated/1.19/client
)
