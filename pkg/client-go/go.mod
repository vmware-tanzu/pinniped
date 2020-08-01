module github.com/suzerain-io/placeholder-name/pkg/client-go

go 1.14

require (
	github.com/golangci/golangci-lint v1.29.0
	github.com/suzerain-io/placeholder-name/pkg/api v0.0.0-00010101000000-000000000000
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e // indirect
	k8s.io/apimachinery v0.19.0-rc.0
	k8s.io/client-go v0.19.0-rc.0
	k8s.io/code-generator v0.19.0-rc.0
)

replace github.com/suzerain-io/placeholder-name/pkg/api => ../api
