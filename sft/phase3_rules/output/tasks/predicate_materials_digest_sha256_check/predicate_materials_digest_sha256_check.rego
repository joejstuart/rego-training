package predicate_materials_digest_sha256_check

import rego.v1

deny contains msg if {
	some material in input.predicate.materials
	not material.digest.sha256
	msg := "sha256 is missing"
}

