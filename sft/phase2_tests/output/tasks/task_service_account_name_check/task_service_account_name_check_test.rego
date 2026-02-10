package task_service_account_name_check_test

import rego.v1

import data.task_service_account_name_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].serviceAccountName` is not `"appstudio-pipeline"`. (Task-level field: serviceAccountName)

# Positive test: valid input should produce no deny violations.
test_task_service_account_name_check_valid if {
	count(task_service_account_name_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"serviceAccountName": "appstudio-pipeline",
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_service_account_name_check_invalid if {
	count(task_service_account_name_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"serviceAccountName": "INVALID_VALUE",
					},
				],
			},
		},
	}
}
