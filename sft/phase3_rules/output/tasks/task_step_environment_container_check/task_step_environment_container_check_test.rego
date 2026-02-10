package task_step_environment_container_check_test

import rego.v1

import data.task_step_environment_container_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].steps[*].environment.container` is not `"init"`. (Task step field: container)

# Positive test: valid input should produce no deny violations.
test_task_step_environment_container_check_valid if {
	count(task_step_environment_container_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"steps": [
							{
								"environment": {
									"container": "init",
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
test_task_step_environment_container_check_invalid if {
	count(task_step_environment_container_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"steps": [
							{
								"environment": {
									"container": "INVALID_VALUE",
								},
							},
						],
					},
				],
			},
		},
	}
}
