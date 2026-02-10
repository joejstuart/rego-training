package task_finished_on_check_test

import rego.v1

import data.task_finished_on_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].finishedOn` is missing or is not a valid ISO-8601 timestamp. (Task-level field: finishedOn)

# Positive test: valid input should produce no deny violations.
test_task_finished_on_check_valid if {
	count(task_finished_on_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"finishedOn": "2025-05-12T12:10:03Z",
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_finished_on_check_invalid if {
	count(task_finished_on_check.deny) > 0
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
