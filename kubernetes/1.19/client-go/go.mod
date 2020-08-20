module github.com/suzerain-io/pinniped/kubernetes/1.19/client-go

go 1.14

require (
	github.com/suzerain-io/pinniped/kubernetes/1.19/api v0.0.0-00010101000000-000000000000
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e // indirect
	k8s.io/apimachinery v0.20.0-alpha.0
	k8s.io/client-go v0.20.0-alpha.0
)

replace github.com/suzerain-io/pinniped/kubernetes/1.19/api => ../api
