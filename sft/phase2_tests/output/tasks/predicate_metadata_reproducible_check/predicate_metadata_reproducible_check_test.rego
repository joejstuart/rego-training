package predicate_metadata_reproducible_check_test

import rego.v1

import data.predicate_metadata_reproducible_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.metadata.reproducible` is not `false`. (Predicate field: metadata.reproducible)

# Positive test: valid input should produce no deny violations.
test_predicate_metadata_reproducible_check_valid if {
	count(predicate_metadata_reproducible_check.deny) == 0
	with input as {
		"predicate": {
			"metadata": {
				"reproducible": false,
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_predicate_metadata_reproducible_check_invalid if {
	count(predicate_metadata_reproducible_check.deny) > 0
	with input as {
		"predicate": {
			"metadata": {
				"reproducible": true,
			},
		},
	}
}
