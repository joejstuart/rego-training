package predicate_metadata_build_started_on_check_test

import rego.v1

import data.predicate_metadata_build_started_on_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.metadata.buildStartedOn` is missing or is not a valid ISO-8601 timestamp. (Predicate field: metadata.buildStartedOn)

# Positive test: valid input should produce no deny violations.
test_predicate_metadata_build_started_on_check_valid if {
	count(predicate_metadata_build_started_on_check.deny) == 0
	with input as {
		"predicate": {
			"metadata": {
				"buildStartedOn": "2025-05-12T12:09:47Z",
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_predicate_metadata_build_started_on_check_invalid if {
	count(predicate_metadata_build_started_on_check.deny) > 0
	with input as {
		"predicate": {
			"metadata": {},
		},
	}
}
