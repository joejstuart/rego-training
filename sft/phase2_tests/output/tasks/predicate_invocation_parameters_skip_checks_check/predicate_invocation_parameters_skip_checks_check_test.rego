package predicate_invocation_parameters_skip_checks_check_test

import rego.v1

import data.predicate_invocation_parameters_skip_checks_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.invocation.parameters.skip-checks` is not `"false"`. (Predicate field: invocation.parameters.skip-checks)

# Positive test: valid input should produce no deny violations.
test_predicate_invocation_parameters_skip_checks_check_valid if {
	count(predicate_invocation_parameters_skip_checks_check.deny) == 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {
					"skip-checks": "false",
				},
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_predicate_invocation_parameters_skip_checks_check_invalid if {
	count(predicate_invocation_parameters_skip_checks_check.deny) > 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {
					"skip-checks": "true",
				},
			},
		},
	}
}
