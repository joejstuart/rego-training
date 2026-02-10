package predicate_materials_check

import rego.v1

deny contains msg if {
	not input.predicate.materials
	msg := "materials is missing"
}

