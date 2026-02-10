package trusted_builder_id_test

import rego.v1

import data.trusted_builder_id

# Instruction: Write a Rego deny rule that rejects the attestation if the `.predicate.builder.id` is not `"https://tekton.dev/chains/v2"` OR the `.predicate.buildType` is not `"tekton.dev/v1beta1/PipelineRun"`. Both fields must match their expected values for the attestation to be accepted.

# Positive test: valid input should produce no deny violations.
test_trusted_builder_id_valid if {
	count(trusted_builder_id.deny) == 0
	with input as {
		"predicate": {
			"builder": {
				"id": "https://tekton.dev/chains/v2",
			},
			"buildType": "tekton.dev/v1beta1/PipelineRun",
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_trusted_builder_id_invalid if {
	count(trusted_builder_id.deny) > 0
	with input as {
		"predicate": {
			"builder": {
				"id": "https://example.com/untrusted",
			},
			"buildType": "tekton.dev/v1beta1/PipelineRun",
		},
	}
}
