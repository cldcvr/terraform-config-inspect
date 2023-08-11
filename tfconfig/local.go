package tfconfig

import "github.com/hashicorp/hcl/v2"

type Local struct {
	Name       string         `json:"name"`
	Expression hcl.Expression `json:"expression"`

	ParentPos SourcePos `json:"parent_pos"`
	Pos       SourcePos `json:"pos"`

	// This may include variables that themselves do not resolve into attribute value (e.g. if condition).
	// module "mod" {
	//	input-name = var.variable_ref != "" ? module.mod.out_ref : other_res.attr
	// }
	Dependencies map[string]AttributeReference `json:"dependencies"`
}

func (b Local) GetDependencies() map[string]AttributeReference {
	return b.Dependencies
}

func (b Local) GetPos() SourcePos {
	return b.Pos
}

func (b Local) GetParentPos() *SourcePos {
	return &b.ParentPos
}
