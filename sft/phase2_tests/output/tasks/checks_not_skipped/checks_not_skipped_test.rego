package checks_not_skipped_test

import rego.v1

import data.checks_not_skipped

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.invocation.parameters["skip-checks"]` is `"true"`. Production builds must not skip checks.

# Positive test: valid input should produce no deny violations.
test_checks_not_skipped_valid if {
	count(checks_not_skipped.deny) == 0
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
test_checks_not_skipped_invalid if {
	count(checks_not_skipped.deny) > 0
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
