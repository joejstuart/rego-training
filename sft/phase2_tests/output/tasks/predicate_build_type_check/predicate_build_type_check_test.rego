package predicate_build_type_check_test

import rego.v1

import data.predicate_build_type_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildType` is not `"tekton.dev/v1beta1/PipelineRun"`. (Build system type identifier)

# Positive test: valid input should produce no deny violations.
test_predicate_build_type_check_valid if {
	count(predicate_build_type_check.deny) == 0
	with input as {
		"predicate": {
			"buildType": "tekton.dev/v1beta1/PipelineRun",
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_predicate_build_type_check_invalid if {
	count(predicate_build_type_check.deny) > 0
	with input as {
		"predicate": {
			"buildType": "INVALID_VALUE",
		},
	}
}
