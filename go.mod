module go.pinniped.dev

go 1.20

// This version taken from https://github.com/kubernetes/apiserver/blob/v0.28.2/go.mod#L14
replace github.com/google/cel-go => github.com/google/cel-go v0.16.1

// This version taken from https://github.com/kubernetes/apiserver/blob/v0.28.2/go.mod#L50
replace k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20230717233707-2695361300d9

require (
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	github.com/chromedp/cdproto v0.0.0-20231007061347-18b01cd81617
	github.com/chromedp/chromedp v0.9.2
	github.com/coreos/go-oidc/v3 v3.6.0
	github.com/coreos/go-semver v0.3.1
	github.com/creack/pty v1.1.18
	github.com/davecgh/go-spew v1.1.1
	github.com/felixge/httpsnoop v1.0.3
	github.com/go-ldap/ldap/v3 v3.4.6
	github.com/go-logr/logr v1.2.4
	github.com/go-logr/stdr v1.2.2
	github.com/go-logr/zapr v1.2.4
	github.com/gofrs/flock v0.8.1
	github.com/golang/mock v1.6.0
	github.com/google/cel-go v0.18.1
	github.com/google/go-cmp v0.5.9
	github.com/google/gofuzz v1.2.0
	github.com/google/uuid v1.3.1
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/websocket v1.5.0
	github.com/joshlf/go-acl v0.0.0-20200411065538-eae00ae38531
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/ory/fosite v0.44.0
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8
	github.com/pkg/errors v0.9.1
	github.com/sclevine/spec v1.4.0
	github.com/spf13/cobra v1.7.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.8.4
	github.com/tdewolff/minify/v2 v2.12.9
	go.uber.org/zap v1.26.0
	golang.org/x/crypto v0.14.0
	golang.org/x/net v0.17.0
	golang.org/x/oauth2 v0.13.0
	golang.org/x/sync v0.4.0
	golang.org/x/term v0.13.0
	golang.org/x/text v0.13.0
	gopkg.in/square/go-jose.v2 v2.6.0
	k8s.io/api v0.28.2
	k8s.io/apiextensions-apiserver v0.28.2
	k8s.io/apimachinery v0.28.2
	k8s.io/apiserver v0.28.2
	k8s.io/client-go v0.28.2
	k8s.io/component-base v0.28.2
	k8s.io/gengo v0.0.0-20230829151522-9cce18d56c01
	k8s.io/klog/v2 v2.100.1
	k8s.io/kube-aggregator v0.28.2
	k8s.io/kube-openapi v0.0.0-20231009201959-f62364c3c354
	k8s.io/utils v0.0.0-20230726121419-3b25d923346b
	sigs.k8s.io/yaml v1.3.0
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/NYTimes/gziphandler v1.1.1 // indirect
	github.com/antlr/antlr4/runtime/Go/antlr/v4 v4.0.0-20230305170008-8188dc5388df // indirect
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/chromedp/sysutil v1.0.0 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/cristalhq/jwt/v4 v4.0.2 // indirect
	github.com/dave/jennifer v1.4.0 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/ecordell/optgen v0.0.6 // indirect
	github.com/emicklei/go-restful/v3 v3.9.0 // indirect
	github.com/evanphx/json-patch v5.6.0+incompatible // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.5 // indirect
	github.com/go-jose/go-jose/v3 v3.0.0 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.2.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v1.1.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/gnostic-models v0.6.8 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.7.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/joshlf/testutil v0.0.0-20170608050642-b5d8aa79d93d // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/goveralls v0.0.11 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ory/go-acc v0.2.8 // indirect
	github.com/ory/go-convenience v0.1.0 // indirect
	github.com/ory/viper v1.7.5 // indirect
	github.com/ory/x v0.0.409 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.1.0 // indirect
	github.com/prometheus/client_golang v1.16.0 // indirect
	github.com/prometheus/client_model v0.4.0 // indirect
	github.com/prometheus/common v0.44.0 // indirect
	github.com/prometheus/procfs v0.10.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spf13/afero v1.8.2 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/subosito/gotenv v1.4.0 // indirect
	github.com/tdewolff/parse/v2 v2.6.8 // indirect
	go.etcd.io/etcd/api/v3 v3.5.9 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.9 // indirect
	go.etcd.io/etcd/client/v3 v3.5.9 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.35.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.35.1 // indirect
	go.opentelemetry.io/otel v1.10.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/internal/retry v1.10.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.10.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.10.0 // indirect
	go.opentelemetry.io/otel/metric v0.31.0 // indirect
	go.opentelemetry.io/otel/sdk v1.10.0 // indirect
	go.opentelemetry.io/otel/trace v1.10.0 // indirect
	go.opentelemetry.io/proto/otlp v0.19.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20220722155223-a9213eeb770e // indirect
	golang.org/x/mod v0.10.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.8.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230726155614-23370e0ffb3e // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230803162519-f966b187b2e5 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230803162519-f966b187b2e5 // indirect
	google.golang.org/grpc v1.57.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.66.6 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/kms v0.28.2 // indirect
	sigs.k8s.io/apiserver-network-proxy/konnectivity-client v0.1.2 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
)
