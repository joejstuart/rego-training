package task_invocation_parameters_hermetic_check_test

import rego.v1

import data.task_invocation_parameters_hermetic_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].invocation.parameters.HERMETIC` is not `"true"`. (Task invocation parameter: HERMETIC)

# Positive test: valid input should produce no deny violations.
test_task_invocation_parameters_hermetic_check_valid if {
	count(task_invocation_parameters_hermetic_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"invocation": {
							"parameters": {
								"HERMETIC": "true",
							},
						},
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_invocation_parameters_hermetic_check_invalid if {
	count(task_invocation_parameters_hermetic_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"invocation": {
							"parameters": {
								"HERMETIC": "false",
							},
						},
					},
				],
			},
		},
	}
}
