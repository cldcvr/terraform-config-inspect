// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfconfig

import (
	"fmt"
	"strconv"
	"strings"
)

// Resource represents a single "resource" or "data" block within a module.
type Resource struct {
	Mode ResourceMode `json:"mode"`
	Type string       `json:"type"`
	Name string       `json:"name"`

	Provider ProviderRef `json:"provider"`

	// All resolved input values to this resource (as <res-input-name>: <value-ref>).
	// resource "res" {
	//	input-name = value-ref (i.e. var.variable_ref, module.mod.out_ref, other_res.attr)
	// }
	Inputs map[string]AttributeReference `json:"inputs"`

	// All references to this resource's attributes by other resoures.
	References map[string][]AttributeReference `json:"references"`

	// All references (not resolved) to other variables (e.g. modules, variables) grouped by name.
	// This may include variables that themselves do not resolve into attribute value (e.g. if condition).
	// module "mod" {
	//	input-name = var.variable_ref != "" ? module.mod.out_ref : other_res.attr
	// }
	Dependencies map[string]AttributeReference `json:"dependencies"`

	Pos SourcePos `json:"pos"`
}

// MapKey returns a string that can be used to uniquely identify the receiver
// in a map[string]*Resource.
func (r *Resource) MapKey() string {
	switch r.Mode {
	case ManagedResourceMode:
		return fmt.Sprintf("%s.%s", r.Type, r.Name)
	case DataResourceMode:
		return fmt.Sprintf("data.%s.%s", r.Type, r.Name)
	default:
		// should never happen
		return fmt.Sprintf("[invalid_mode!].%s.%s", r.Type, r.Name)
	}
}

// ResourceMode represents the "mode" of a resource, which is used to
// distinguish between managed resources ("resource" blocks in config) and
// data resources ("data" blocks in config).
type ResourceMode rune

const InvalidResourceMode ResourceMode = 0
const ManagedResourceMode ResourceMode = 'M'
const DataResourceMode ResourceMode = 'D'

func (m ResourceMode) String() string {
	switch m {
	case ManagedResourceMode:
		return "managed"
	case DataResourceMode:
		return "data"
	default:
		return ""
	}
}

// MarshalJSON implements encoding/json.Marshaler.
func (m ResourceMode) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(m.String())), nil
}

func resourceTypeDefaultProviderName(typeName string) string {
	if underPos := strings.IndexByte(typeName, '_'); underPos != -1 {
		return typeName[:underPos]
	}
	return typeName
}

func (b Resource) GetDependencies() map[string]AttributeReference {
	return b.Dependencies
}

func (b Resource) GetPos() SourcePos {
	return b.Pos
}

func (b Resource) GeProviderName() string {
	return b.Provider.Name
}
