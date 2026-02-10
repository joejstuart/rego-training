package predicate_invocation_parameters_skip_checks_check

import rego.v1

deny contains msg if {
	input.predicate.invocation.parameters["skip-checks"] != "false"
	msg := sprintf("skip-checks is %v, expected false", [input.predicate.invocation.parameters["skip-checks"]])
}

