module github.com/suzerain-io/placeholder-name

go 1.14

require (
	github.com/golang/mock v1.4.3
	github.com/golangci/golangci-lint v1.29.0
	github.com/google/go-cmp v0.5.0
	github.com/sclevine/spec v1.4.0
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.6.1
	github.com/suzerain-io/controller-go v0.0.0-20200730212956-7f99b569ca9f
	github.com/suzerain-io/placeholder-name-api v0.0.0-20200731224558-ff85679d3364
	github.com/suzerain-io/placeholder-name-client-go v0.0.0-20200731225637-b994efe19486
	github.com/suzerain-io/placeholder-name/pkg/client v0.0.0-00010101000000-000000000000
	k8s.io/api v0.19.0-rc.0
	k8s.io/apimachinery v0.19.0-rc.0
	k8s.io/apiserver v0.19.0-rc.0
	k8s.io/client-go v0.19.0-rc.0
	k8s.io/component-base v0.19.0-rc.0
	k8s.io/klog/v2 v2.2.0
	k8s.io/kube-aggregator v0.19.0-rc.0
	sigs.k8s.io/yaml v1.2.0
)

replace github.com/suzerain-io/placeholder-name/pkg/client => ./pkg/client
