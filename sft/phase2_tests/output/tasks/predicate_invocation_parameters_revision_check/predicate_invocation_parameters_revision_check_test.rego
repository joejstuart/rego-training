package predicate_invocation_parameters_revision_check_test

import rego.v1

import data.predicate_invocation_parameters_revision_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.invocation.parameters.revision` is missing or does not match the expected sha256 digest format. (Predicate field: invocation.parameters.revision)

# Positive test: valid input should produce no deny violations.
test_predicate_invocation_parameters_revision_check_valid if {
	count(predicate_invocation_parameters_revision_check.deny) == 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {
					"revision": "356a767377f0917039b096677333b16bb6c8fbbb",
				},
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_predicate_invocation_parameters_revision_check_invalid if {
	count(predicate_invocation_parameters_revision_check.deny) > 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {},
			},
		},
	}
}
