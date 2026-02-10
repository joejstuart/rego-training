package task_started_on_check_test

import rego.v1

import data.task_started_on_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].startedOn` is missing or is not a valid ISO-8601 timestamp. (Task-level field: startedOn)

# Positive test: valid input should produce no deny violations.
test_task_started_on_check_valid if {
	count(task_started_on_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"startedOn": "2025-05-12T12:09:57Z",
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_started_on_check_invalid if {
	count(task_started_on_check.deny) > 0
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
