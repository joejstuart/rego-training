package predicate_builder_id_check

import rego.v1

deny contains msg if {
	input.predicate.builder.id != "https://tekton.dev/chains/v2"
	msg := sprintf("id is %v, expected https://tekton.dev/chains/v2", [input.predicate.builder.id])
}

