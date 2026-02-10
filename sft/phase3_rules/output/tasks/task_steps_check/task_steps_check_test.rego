package task_steps_check_test

import rego.v1

import data.task_steps_check

# Instruction: Write a Rego deny rule that rejects the attestation if the field `.predicate.buildConfig.tasks[*].steps` is missing or empty. (Task-level field: steps)

# Positive test: valid input should produce no deny violations.
test_task_steps_check_valid if {
	count(task_steps_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"steps": "example-value",
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_steps_check_invalid if {
	count(task_steps_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{},
				],
			},
		},
	}
}
