package all_tasks_have_service_account_test

import rego.v1

import data.all_tasks_have_service_account

# Instruction: Write a Rego deny rule that rejects the attestation if any task in `.predicate.buildConfig.tasks` is missing the `serviceAccountName` field or it is empty.

# Positive test: valid input should produce no deny violations.
test_all_tasks_have_service_account_valid if {
	count(all_tasks_have_service_account.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build",
						"serviceAccountName": "pipeline",
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_all_tasks_have_service_account_invalid if {
	count(all_tasks_have_service_account.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build",
						"serviceAccountName": "pipeline",
					},
					{
						"name": "test",
						"serviceAccountName": "",
					},
				],
			},
		},
	}
}
