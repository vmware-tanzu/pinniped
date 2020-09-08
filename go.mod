module github.com/suzerain-io/pinniped

go 1.14

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/go-logr/logr v0.2.0
	github.com/golang/mock v1.4.4
	github.com/golangci/golangci-lint v1.31.0
	github.com/google/go-cmp v0.5.2
	github.com/sclevine/spec v1.4.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.6.1
	github.com/suzerain-io/pinniped/generated/1.19/apis v0.0.0-00010101000000-000000000000
	github.com/suzerain-io/pinniped/generated/1.19/client v0.0.0-00010101000000-000000000000
	k8s.io/api v0.19.0
	k8s.io/apimachinery v0.19.0
	k8s.io/apiserver v0.19.0
	k8s.io/client-go v0.19.0
	k8s.io/component-base v0.19.0
	k8s.io/klog/v2 v2.3.0
	k8s.io/kube-aggregator v0.19.0
	k8s.io/utils v0.0.0-20200729134348-d5654de09c73
	sigs.k8s.io/yaml v1.2.0
)

replace (
	github.com/suzerain-io/pinniped/generated/1.19/apis => ./generated/1.19/apis
	github.com/suzerain-io/pinniped/generated/1.19/client => ./generated/1.19/client
)
