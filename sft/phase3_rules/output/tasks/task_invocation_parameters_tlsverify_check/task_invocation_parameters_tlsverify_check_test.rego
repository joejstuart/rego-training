package task_invocation_parameters_tlsverify_check_test

import rego.v1

import data.task_invocation_parameters_tlsverify_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].invocation.parameters.TLSVERIFY` is not `"true"`. (Task invocation parameter: TLSVERIFY)

# Positive test: valid input should produce no deny violations.
test_task_invocation_parameters_tlsverify_check_valid if {
	count(task_invocation_parameters_tlsverify_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"invocation": {
							"parameters": {
								"TLSVERIFY": "true",
							},
						},
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_invocation_parameters_tlsverify_check_invalid if {
	count(task_invocation_parameters_tlsverify_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"invocation": {
							"parameters": {
								"TLSVERIFY": "false",
							},
						},
					},
				],
			},
		},
	}
}
