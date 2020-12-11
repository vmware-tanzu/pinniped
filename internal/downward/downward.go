// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package downward implements a client interface for interacting with Kubernetes "downwardAPI" volumes.
// See https://kubernetes.io/docs/tasks/inject-data-application/downward-api-volume-expose-pod-information/.
package downward

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"

	"go.pinniped.dev/internal/plog"
)

// PodInfo contains pod metadata about the current pod.
type PodInfo struct {
	// Namespace where the current pod is running.
	Namespace string

	// Name of the current pod.
	Name string

	// Labels of the current pod.
	Labels map[string]string
}

// Load pod metadata from a downwardAPI volume directory.
func Load(directory string) (*PodInfo, error) {
	var result PodInfo
	ns, err := ioutil.ReadFile(filepath.Join(directory, "namespace"))
	if err != nil {
		return nil, fmt.Errorf("could not load namespace: %w", err)
	}
	result.Namespace = strings.TrimSpace(string(ns))

	name, err := ioutil.ReadFile(filepath.Join(directory, "name"))
	if err != nil {
		plog.Warning("could not read 'name' downward API file")
	} else {
		result.Name = strings.TrimSpace(string(name))
	}

	labels, err := ioutil.ReadFile(filepath.Join(directory, "labels"))
	if err != nil {
		return nil, fmt.Errorf("could not load labels: %w", err)
	}
	result.Labels, err = parseMap(labels)
	if err != nil {
		return nil, fmt.Errorf("could not parse labels: %w", err)
	}
	return &result, nil
}

// parseMap parses the key/value format emitted by the Kubernetes Downward API for pod labels and annotations.
// See https://kubernetes.io/docs/tasks/inject-data-application/downward-api-volume-expose-pod-information/.
// See https://github.com/kubernetes/kubernetes/blob/4b2cb072dba10227083b16731f019f096c581787/pkg/fieldpath/fieldpath.go#L28.
func parseMap(input []byte) (map[string]string, error) {
	result := map[string]string{}
	for _, line := range bytes.Split(input, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		parts := bytes.SplitN(line, []byte("="), 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("expected 2 parts, found %d: %w", len(parts), io.ErrShortBuffer)
		}
		value, err := strconv.Unquote(string(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid quoted value: %w", err)
		}
		result[string(parts[0])] = value
	}
	return result, nil
}
