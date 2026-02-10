package predicate_invocation_parameters_output_image_check_test

import rego.v1

import data.predicate_invocation_parameters_output_image_check

# Instruction: Write a Rego deny rule that rejects the attestation if the field `.predicate.invocation.parameters.output-image` is missing. (Predicate field: invocation.parameters.output-image)

# Positive test: valid input should produce no deny violations.
test_predicate_invocation_parameters_output_image_check_valid if {
	count(predicate_invocation_parameters_output_image_check.deny) == 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {
					"output-image": "quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container:356a767377f0917039b096677333b16bb6c8fbbb",
				},
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_predicate_invocation_parameters_output_image_check_invalid if {
	count(predicate_invocation_parameters_output_image_check.deny) > 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {},
			},
		},
	}
}
