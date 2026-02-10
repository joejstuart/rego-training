package all_materials_have_uri

import rego.v1

deny contains msg if {
	some material in input.predicate.materials
	not material.uri
	msg := "material is missing uri field"
}
