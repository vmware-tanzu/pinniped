module go.pinniped.dev

go 1.14

require (
	cloud.google.com/go v0.60.0 // indirect
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	github.com/coreos/go-oidc/v3 v3.0.0
	github.com/davecgh/go-spew v1.1.1
	github.com/go-logr/logr v0.3.0
	github.com/go-logr/stdr v0.2.0
	github.com/gofrs/flock v0.8.0
	github.com/golang/mock v1.4.4
	github.com/google/go-cmp v0.5.4
	github.com/google/gofuzz v1.2.0
	github.com/gorilla/securecookie v1.1.1
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/oleiade/reflections v1.0.1 // indirect
	github.com/onsi/ginkgo v1.13.0 // indirect
	github.com/ory/fosite v0.36.0
	github.com/pkg/browser v0.0.0-20201207095918-0426ae3fba23
	github.com/pkg/errors v0.9.1
	github.com/sclevine/agouti v3.0.0+incompatible
	github.com/sclevine/spec v1.4.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.6.1
	go.pinniped.dev/generated/1.20/apis v0.0.0-00010101000000-000000000000
	go.pinniped.dev/generated/1.20/client v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.0.0-20201217014255-9d1352758620
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a
	golang.org/x/tools v0.0.0-20200825202427-b303f430e36d // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/square/go-jose.v2 v2.5.1
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776 // indirect
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/apiserver v0.20.1
	k8s.io/client-go v0.20.1
	k8s.io/component-base v0.20.1
	k8s.io/gengo v0.0.0-20201113003025-83324d819ded
	k8s.io/klog/v2 v2.4.0
	k8s.io/kube-aggregator v0.20.1
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920
	sigs.k8s.io/yaml v1.2.0
)

replace (
	go.pinniped.dev/generated/1.20/apis => ./generated/1.20/apis
	go.pinniped.dev/generated/1.20/client => ./generated/1.20/client
)
