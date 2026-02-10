package all_tasks_have_steps_test

import rego.v1

import data.all_tasks_have_steps

# Instruction: Write a Rego deny rule that rejects the attestation if any task in `.predicate.buildConfig.tasks` has an empty or missing `steps` array.

# Positive test: valid input should produce no deny violations.
test_all_tasks_have_steps_valid if {
	count(all_tasks_have_steps.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build",
						"steps": [
							{
								"environment": {
									"container": "build",
									"image": "quay.io/ex",
								},
							},
						],
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_all_tasks_have_steps_invalid if {
	count(all_tasks_have_steps.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build",
						"steps": [
							{
								"environment": {
									"container": "build",
									"image": "quay.io/ex",
								},
							},
						],
					},
					{
						"name": "test",
						"steps": [],
					},
				],
			},
		},
	}
}
