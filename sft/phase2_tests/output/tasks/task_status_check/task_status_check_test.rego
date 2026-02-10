package task_status_check_test

import rego.v1

import data.task_status_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].status` is not `"Succeeded"`. (Task-level field: status)

# Positive test: valid input should produce no deny violations.
test_task_status_check_valid if {
	count(task_status_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"status": "Succeeded",
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_status_check_invalid if {
	count(task_status_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"status": "INVALID_VALUE",
					},
				],
			},
		},
	}
}
