package checks_not_skipped

import rego.v1

deny contains msg if {
	input.predicate.invocation.parameters["skip-checks"] == "true"
	msg := "skip-checks is set to true, production builds must not skip checks"
}
