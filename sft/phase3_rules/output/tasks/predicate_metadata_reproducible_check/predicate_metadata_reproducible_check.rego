package predicate_metadata_reproducible_check

import rego.v1

deny contains msg if {
	input.predicate.metadata.reproducible != false
	msg := "reproducible must be false"
}

