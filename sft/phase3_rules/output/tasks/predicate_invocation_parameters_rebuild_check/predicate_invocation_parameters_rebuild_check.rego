package predicate_invocation_parameters_rebuild_check

import rego.v1

deny contains msg if {
	input.predicate.invocation.parameters.rebuild != "false"
	msg := sprintf("rebuild is %v, expected false", [input.predicate.invocation.parameters.rebuild])
}

