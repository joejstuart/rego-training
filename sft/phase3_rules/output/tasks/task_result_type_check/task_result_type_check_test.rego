package task_result_type_check_test

import rego.v1

import data.task_result_type_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].results[*].type` is not `"string"`. (Task result field: type)

# Positive test: valid input should produce no deny violations.
test_task_result_type_check_valid if {
	count(task_result_type_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"results": [
							{
								"type": "string",
							},
						],
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_result_type_check_invalid if {
	count(task_result_type_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"results": [
							{
								"type": "INVALID_VALUE",
							},
						],
					},
				],
			},
		},
	}
}
