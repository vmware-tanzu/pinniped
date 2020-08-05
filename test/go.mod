module github.com/suzerain-io/placeholder-name/test

go 1.14

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/stretchr/testify v1.6.1
	github.com/suzerain-io/placeholder-name-api v0.0.0-20200731224558-ff85679d3364
	github.com/suzerain-io/placeholder-name-client-go v0.0.0-20200731225637-b994efe19486
	github.com/suzerain-io/placeholder-name/pkg/client v0.0.0-00010101000000-000000000000
	k8s.io/api v0.19.0-rc.0
	k8s.io/apimachinery v0.19.0-rc.0
	k8s.io/client-go v0.19.0-rc.0
)

replace github.com/suzerain-io/placeholder-name/pkg/client => ../pkg/client
