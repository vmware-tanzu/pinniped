/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"github.com/suzerain-io/placeholder-name/pkg/handlers"
	"log"
	"net/http"
)

func main() {
	log.Fatal(http.ListenAndServe(":8080", handlers.New()))
}
