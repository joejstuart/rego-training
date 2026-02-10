package all_tasks_succeeded_test

import rego.v1

import data.all_tasks_succeeded

# Instruction: Write a Rego deny rule that rejects the attestation if any task in `.predicate.buildConfig.tasks` does not have `status` equal to `"Succeeded"`.

# Positive test: valid input should produce no deny violations.
test_all_tasks_succeeded_valid if {
	count(all_tasks_succeeded.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build",
						"status": "Succeeded",
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_all_tasks_succeeded_invalid if {
	count(all_tasks_succeeded.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build",
						"status": "Succeeded",
					},
					{
						"name": "test",
						"status": "Failed",
					},
				],
			},
		},
	}
}
