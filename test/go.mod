module github.com/suzerain-io/placeholder-name/test

go 1.14

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/stretchr/testify v1.6.1
	github.com/suzerain-io/placeholder-name/kubernetes/1.19/api v0.0.0-00010101000000-000000000000
	github.com/suzerain-io/placeholder-name/kubernetes/1.19/client-go v0.0.0-00010101000000-000000000000
	github.com/suzerain-io/placeholder-name/pkg/client v0.0.0-00010101000000-000000000000
	k8s.io/api v0.19.0-rc.0
	k8s.io/apimachinery v0.19.0-rc.0
	k8s.io/client-go v0.19.0-rc.0
	k8s.io/kube-aggregator v0.18.6
)

replace (
	github.com/suzerain-io/placeholder-name/kubernetes/1.19/api => ../kubernetes/1.19/api
	github.com/suzerain-io/placeholder-name/kubernetes/1.19/client-go => ../kubernetes/1.19/client-go
	github.com/suzerain-io/placeholder-name/pkg/client => ../pkg/client
)
