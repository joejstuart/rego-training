package task_invocation_parameters_image_check_test

import rego.v1

import data.task_invocation_parameters_image_check

# Instruction: Write a Rego deny rule that rejects the attestation if the field `.predicate.buildConfig.tasks[*].invocation.parameters.IMAGE` is missing. (Task invocation parameter: IMAGE)

# Positive test: valid input should produce no deny violations.
test_task_invocation_parameters_image_check_valid if {
	count(task_invocation_parameters_image_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"invocation": {
							"parameters": {
								"IMAGE": "quay.io/redhat-user-workloads/rhtap-contract-tenant/golden-container/golden-container:356a767377f0917039b096677333b16bb6c8fbbb-amd64",
							},
						},
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_invocation_parameters_image_check_invalid if {
	count(task_invocation_parameters_image_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"invocation": {
							"parameters": {},
						},
					},
				],
			},
		},
	}
}
