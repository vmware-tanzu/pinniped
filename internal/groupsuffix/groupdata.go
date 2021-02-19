// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package groupsuffix

import (
	"k8s.io/apimachinery/pkg/runtime/schema"

	identityv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
)

type GroupData schema.GroupVersion

func (d GroupData) APIServiceName() string {
	return d.Version + "." + d.Group
}

func ConciergeAggregatedGroups(apiGroupSuffix string) (login, identity GroupData) {
	loginConciergeAPIGroup, ok1 := Replace(loginv1alpha1.GroupName, apiGroupSuffix)
	identityConciergeAPIGroup, ok2 := Replace(identityv1alpha1.GroupName, apiGroupSuffix)

	if valid := ok1 && ok2; !valid {
		panic("static group input is invalid")
	}

	return GroupData{
			Group:   loginConciergeAPIGroup,
			Version: loginv1alpha1.SchemeGroupVersion.Version,
		}, GroupData{
			Group:   identityConciergeAPIGroup,
			Version: identityv1alpha1.SchemeGroupVersion.Version,
		}
}
