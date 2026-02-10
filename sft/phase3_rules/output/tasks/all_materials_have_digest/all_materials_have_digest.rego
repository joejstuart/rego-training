package all_materials_have_digest

import rego.v1

deny contains msg if {
	some material in input.predicate.materials
	not material.digest
	msg := "material is missing digest"
}
