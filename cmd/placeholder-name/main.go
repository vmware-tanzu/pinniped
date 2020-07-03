package main

import (
	"fmt"
	"github.com/suzerain-io/placeholder-name/pkg/hello"
)

func main() {
	fmt.Println(hello.NewHelloSayer().SayHello())
}
