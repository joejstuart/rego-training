package all_tasks_have_name_test

import rego.v1

import data.all_tasks_have_name

# Instruction: Write a Rego deny rule that rejects the attestation if any task in `.predicate.buildConfig.tasks` is missing the `name` field.

# Positive test: valid input should produce no deny violations.
test_all_tasks_have_name_valid if {
	count(all_tasks_have_name.deny) == 0
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
test_all_tasks_have_name_invalid if {
	count(all_tasks_have_name.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build",
						"status": "Succeeded",
					},
					{
						"status": "Succeeded",
					},
				],
			},
		},
	}
}
