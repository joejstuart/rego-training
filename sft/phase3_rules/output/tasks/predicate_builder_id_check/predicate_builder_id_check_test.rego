package predicate_builder_id_check_test

import rego.v1

import data.predicate_builder_id_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.builder.id` is not `"https://tekton.dev/chains/v2"`. (Builder identity URI)

# Positive test: valid input should produce no deny violations.
test_predicate_builder_id_check_valid if {
	count(predicate_builder_id_check.deny) == 0
	with input as {
		"predicate": {
			"builder": {
				"id": "https://tekton.dev/chains/v2",
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_predicate_builder_id_check_invalid if {
	count(predicate_builder_id_check.deny) > 0
	with input as {
		"predicate": {
			"builder": {
				"id": "https://example.com/INVALID",
			},
		},
	}
}
