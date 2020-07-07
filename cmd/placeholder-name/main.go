/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"
	"net/http"

	"github.com/suzerain-io/placeholder-name/pkg/handlers"
)

func main() {
	log.Fatal(http.ListenAndServe(":8080", handlers.New()))
}
