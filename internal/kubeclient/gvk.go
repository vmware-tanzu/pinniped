// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func maybeRestoreGVK(serializer runtime.Serializer, respData []byte, result *mutationResult) ([]byte, error) {
	if !result.gvkChanged {
		return respData, nil
	}

	// the body could be an API status, random trash or the actual object we want
	unknown := &runtime.Unknown{}
	_ = runtime.DecodeInto(serializer, respData, unknown) // we do not care about the error

	doesNotNeedGVKFix := len(unknown.Raw) == 0 || unknown.GroupVersionKind() != result.newGVK

	if doesNotNeedGVKFix {
		return respData, nil
	}

	return restoreGVK(serializer, unknown, result.origGVK)
}

func restoreGVK(encoder runtime.Encoder, unknown *runtime.Unknown, gvk schema.GroupVersionKind) ([]byte, error) {
	typeMeta := runtime.TypeMeta{}
	typeMeta.APIVersion, typeMeta.Kind = gvk.ToAPIVersionAndKind()

	newUnknown := &runtime.Unknown{}
	*newUnknown = *unknown
	newUnknown.TypeMeta = typeMeta

	switch newUnknown.ContentType {
	case runtime.ContentTypeJSON:
		// json is messy if we want to avoid decoding the whole object
		keysOnly := map[string]json.RawMessage{}

		// get the keys.  this does not preserve order.
		if err := json.Unmarshal(newUnknown.Raw, &keysOnly); err != nil {
			return nil, fmt.Errorf("failed to unmarshall json keys: %w", err)
		}

		// turn the type meta into JSON bytes
		typeMetaBytes, err := json.Marshal(typeMeta)
		if err != nil {
			return nil, fmt.Errorf("failed to marshall type meta: %w", err)
		}

		// overwrite the type meta keys with the new data
		if err := json.Unmarshal(typeMetaBytes, &keysOnly); err != nil {
			return nil, fmt.Errorf("failed to type meta keys: %w", err)
		}

		// marshall everything back to bytes
		newRaw, err := json.Marshal(keysOnly)
		if err != nil {
			return nil, fmt.Errorf("failed to marshall new raw: %w", err)
		}

		// we could just return the bytes but it feels weird to not use the encoder
		newUnknown.Raw = newRaw

	case runtime.ContentTypeProtobuf:
		// protobuf is easy because of the unknown wrapper
		// newUnknown.Raw already contains the correct data we need

	default:
		return nil, fmt.Errorf("unknown content type: %s", newUnknown.ContentType) // this should never happen
	}

	return runtime.Encode(encoder, newUnknown)
}
