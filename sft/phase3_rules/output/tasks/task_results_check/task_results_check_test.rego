package task_results_check_test

import rego.v1

import data.task_results_check

# Instruction: Write a Rego deny rule that rejects the attestation if the field `.predicate.buildConfig.tasks[*].results` is missing or empty. (Task-level field: results)

# Positive test: valid input should produce no deny violations.
test_task_results_check_valid if {
	count(task_results_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"results": "example-value",
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_results_check_invalid if {
	count(task_results_check.deny) > 0
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
