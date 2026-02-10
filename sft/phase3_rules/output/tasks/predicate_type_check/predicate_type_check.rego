package predicate_type_check

import rego.v1

deny contains msg if {
	input.predicateType != "https://slsa.dev/provenance/v0.2"
	msg := sprintf("predicateType is %v, expected https://slsa.dev/provenance/v0.2", [input.predicateType])
}

