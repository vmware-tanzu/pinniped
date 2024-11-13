// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package auditid

import (
	"net/http"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/types"
	apiserveraudit "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/audit"
)

// NewRequestWithAuditID is public for use in unit tests. Production code should use WithAuditID().
func NewRequestWithAuditID(r *http.Request, newAuditIDFunc func() string) (*http.Request, string) {
	ctx := audit.WithAuditContext(r.Context())
	r = r.WithContext(ctx)

	auditID := newAuditIDFunc()
	audit.WithAuditID(ctx, types.UID(auditID))

	return r, auditID
}

func WithAuditID(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add a randomly generated request ID to the context for this request.
		r, auditID := NewRequestWithAuditID(r, func() string {
			return uuid.New().String()
		})

		// Send the Audit-ID response header.
		w.Header().Set(apiserveraudit.HeaderAuditID, auditID)

		handler.ServeHTTP(w, r)
	})
}
