package task_name_check_test

import rego.v1

import data.task_name_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].name` is not `"init"`. (Task-level field: name)

# Positive test: valid input should produce no deny violations.
test_task_name_check_valid if {
	count(task_name_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "init",
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_name_check_invalid if {
	count(task_name_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "INVALID_VALUE",
					},
				],
			},
		},
	}
}
