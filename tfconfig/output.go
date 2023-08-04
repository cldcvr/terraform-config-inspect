// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tfconfig

// Output represents a single output from a Terraform module.
type Output struct {
	Name string `json:"name"`
	// Referenced resource attribute
	Value       ResourceAttributeReference `json:"value"`
	Description string                     `json:"description,omitempty"`
	Sensitive   bool                       `json:"sensitive,omitempty"`
	Pos         SourcePos                  `json:"pos"` // All references (not resolved) to other variables (e.g. modules, variables) grouped by name.

	// This may include variables that themselves do not resolve into attribute value (e.g. if condition).
	// module "mod" {
	//	input-name = var.variable_ref != "" ? module.mod.out_ref : other_res.attr
	// }
	Dependencies map[string]AttributeReference `json:"dependencies"`
}

func (v Output) GetName() string {
	return v.Name
}

func (v Output) GetDescription() string {
	return v.Description
}

func (v Output) IsRequired() bool {
	return false
}

func (v Output) IsComputed() bool {
	return true
}
