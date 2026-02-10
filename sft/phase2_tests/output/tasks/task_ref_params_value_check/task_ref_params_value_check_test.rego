package task_ref_params_value_check_test

import rego.v1

import data.task_ref_params_value_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].ref.params[*].value` is not `"init"`. (Task reference field: value)

# Positive test: valid input should produce no deny violations.
test_task_ref_params_value_check_valid if {
	count(task_ref_params_value_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"ref": {
							"params": [
								{
									"value": "init",
								},
							],
						},
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_ref_params_value_check_invalid if {
	count(task_ref_params_value_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"ref": {
							"params": [
								{
									"value": "INVALID_VALUE",
								},
							],
						},
					},
				],
			},
		},
	}
}
