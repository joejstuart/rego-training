package predicate_invocation_parameters_revision_check

import rego.v1

deny contains msg if {
	not input.predicate.invocation.parameters.revision
	msg := "revision is missing"
}

