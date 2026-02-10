package task_result_name_check_test

import rego.v1

import data.task_result_name_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].results[*].name` is not `"build"`. (Task result field: name)

# Positive test: valid input should produce no deny violations.
test_task_result_name_check_valid if {
	count(task_result_name_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"results": [
							{
								"name": "build",
							},
						],
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_result_name_check_invalid if {
	count(task_result_name_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"results": [
							{
								"name": "INVALID_VALUE",
							},
						],
					},
				],
			},
		},
	}
}
