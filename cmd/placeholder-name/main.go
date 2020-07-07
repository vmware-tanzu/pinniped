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
	addr := ":8080"
	log.Printf("Starting server on %v", addr)
	log.Fatal(http.ListenAndServe(addr, handlers.New()))
}
