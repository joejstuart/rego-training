package task_result_value_check_test

import rego.v1

import data.task_result_value_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].results[*].value` is not `"true"`. (Task result field: value)

# Positive test: valid input should produce no deny violations.
test_task_result_value_check_valid if {
	count(task_result_value_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"results": [
							{
								"value": "true",
							},
						],
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_result_value_check_invalid if {
	count(task_result_value_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"results": [
							{
								"value": "false",
							},
						],
					},
				],
			},
		},
	}
}
