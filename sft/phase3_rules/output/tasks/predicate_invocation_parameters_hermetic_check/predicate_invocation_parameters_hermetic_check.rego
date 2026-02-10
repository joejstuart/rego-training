package predicate_invocation_parameters_hermetic_check

import rego.v1

deny contains msg if {
	input.predicate.invocation.parameters.hermetic != "true"
	msg := sprintf("hermetic is %v, expected true", [input.predicate.invocation.parameters.hermetic])
}

