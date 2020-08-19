module github.com/suzerain-io/placeholder-name

go 1.14

require (
	github.com/go-logr/logr v0.2.0
	github.com/golang/mock v1.4.3
	github.com/golangci/golangci-lint v1.30.0
	github.com/google/go-cmp v0.5.0
	github.com/sclevine/spec v1.4.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.6.1
	github.com/suzerain-io/controller-go v0.0.0-20200730212956-7f99b569ca9f
	github.com/suzerain-io/placeholder-name/kubernetes/1.19/api v0.0.0-00010101000000-000000000000
	github.com/suzerain-io/placeholder-name/kubernetes/1.19/client-go v0.0.0-00010101000000-000000000000
	github.com/suzerain-io/placeholder-name/pkg/client v0.0.0-00010101000000-000000000000
	k8s.io/api v0.19.0-rc.0
	k8s.io/apimachinery v0.19.0-rc.0
	k8s.io/apiserver v0.19.0-rc.0
	k8s.io/client-go v0.19.0-rc.0
	k8s.io/component-base v0.19.0-rc.0
	k8s.io/klog/v2 v2.2.0
	k8s.io/kube-aggregator v0.19.0-rc.0
	k8s.io/utils v0.0.0-20200619165400-6e3d28b6ed19
	sigs.k8s.io/yaml v1.2.0
)

replace (
	github.com/suzerain-io/placeholder-name/kubernetes/1.19/api => ./kubernetes/1.19/api
	github.com/suzerain-io/placeholder-name/kubernetes/1.19/client-go => ./kubernetes/1.19/client-go
	github.com/suzerain-io/placeholder-name/pkg/client => ./pkg/client
)
