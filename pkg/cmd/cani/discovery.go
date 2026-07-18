package cani

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

// resourceInfo is what applyDiscovery learns about a resource from the API.
type resourceInfo struct {
	group      string
	namespaced bool
}

// applyDiscovery aligns the request with the cluster's API surface the way
// kubectl does before submitting an access review:
//
//   - fills in the API group when the user omitted it (so "deployments"
//     resolves to the apps group instead of being checked against the core
//     group), and
//   - clears the namespace for cluster-scoped resources (so "get nodes -n
//     default" doesn't credit namespaced RoleBindings).
//
// Discovery failures and unknown resources degrade to a warning on errOut and
// the request is evaluated as-is.
func (o *RbacWhyOptions) applyDiscovery(restConfig *rest.Config, request *rbac.PermissionRequest) {
	// Non-resource URLs (e.g. /healthz) are not part of API discovery.
	if request.NonResourceURL != "" {
		return
	}

	dc, err := discovery.NewDiscoveryClientForConfig(restConfig)
	if err != nil {
		_, _ = fmt.Fprintf(o.ErrOut, "Warning: failed to build discovery client (%v); evaluating request as-is\n", err)
		return
	}

	_, lists, err := dc.ServerGroupsAndResources()
	// Partial discovery results (some group unavailable) are still usable.
	if err != nil && len(lists) == 0 {
		_, _ = fmt.Fprintf(o.ErrOut, "Warning: API discovery failed (%v); evaluating request as-is\n", err)
		return
	}

	matches := findResourceMatches(lists, request.Resource)
	if len(matches) == 0 {
		_, _ = fmt.Fprintf(o.ErrOut, "Warning: resource %q not found via API discovery; evaluating request as-is\n", request.Resource)
		return
	}

	var chosen *resourceInfo
	if hasExplicitGroup(request) {
		for i := range matches {
			if matches[i].group == request.APIGroup {
				chosen = &matches[i]
				break
			}
		}
		if chosen == nil {
			_, _ = fmt.Fprintf(o.ErrOut, "Warning: resource %q not found in API group %q via discovery; evaluating request as-is\n", request.Resource, request.APIGroup)
			return
		}
	} else {
		// No explicit group: prefer the core group like kubectl, else take
		// the first discovered group.
		for i := range matches {
			if matches[i].group == "" {
				chosen = &matches[i]
				break
			}
		}
		if chosen == nil {
			chosen = &matches[0]
			request.APIGroup = chosen.group
			_, _ = fmt.Fprintf(o.ErrOut, "Note: resolved resource %q to API group %q\n", request.Resource, chosen.group)
		}
	}

	if !chosen.namespaced && request.Namespace != "" {
		_, _ = fmt.Fprintf(o.ErrOut, "Note: %q is cluster-scoped; ignoring namespace %q\n", request.Resource, request.Namespace)
		request.Namespace = ""
	}
}

// hasExplicitGroup reports whether the user named an API group. The core
// group can't be requested explicitly (it's spelled ""), so empty means
// "unspecified".
func hasExplicitGroup(request *rbac.PermissionRequest) bool {
	return request.APIGroup != ""
}

// findResourceMatches scans discovery lists for top-level resources whose
// plural name equals the requested resource, deduplicated by API group.
func findResourceMatches(lists []*metav1.APIResourceList, resource string) []resourceInfo {
	var matches []resourceInfo
	seen := make(map[string]bool)
	for _, list := range lists {
		if list == nil {
			continue
		}
		gv, err := schema.ParseGroupVersion(list.GroupVersion)
		if err != nil {
			continue
		}
		for _, res := range list.APIResources {
			// Skip subresources; scope comes from the parent resource.
			if strings.Contains(res.Name, "/") {
				continue
			}
			if res.Name != resource {
				continue
			}
			group := res.Group
			if group == "" {
				group = gv.Group
			}
			if seen[group] {
				continue
			}
			seen[group] = true
			matches = append(matches, resourceInfo{group: group, namespaced: res.Namespaced})
		}
	}
	return matches
}
