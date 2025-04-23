package registry_auth

import "strings"

// https://distribution.github.io/distribution/spec/auth/scope/#resource-scope-grammar

// ResourceScope records actions on a named and typed resource.
type ResourceScope struct {
	// The type of resource hosted by the service.
	Type string `json:"type"`

	// The name of the resource of the given type hosted by the service.
	Name string `json:"name"`

	// An array of strings which give the actions authorized on this resource.
	Actions []string `json:"actions"`
}

func parseResourceScope(text string) *ResourceScope {
	parts := strings.Split(text, ":")
	if len(parts) != 3 {
		return nil
	}
	return &ResourceScope{
		Type:    parts[0],
		Name:    parts[1],
		Actions: strings.Split(parts[2], ","),
	}
}

type Scope []*ResourceScope

func parseScope(text string) Scope {
	scope := Scope{}
	for _, part := range strings.Split(text, " ") {
		resourceScope := parseResourceScope(part)
		if resourceScope == nil {
			continue
		}
		scope = append(scope, resourceScope)
	}
	return scope
}
