package task_invocation_parameters_commit_sha_check_test

import rego.v1

import data.task_invocation_parameters_commit_sha_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].invocation.parameters.COMMIT_SHA` is missing or does not match the expected sha256 digest format. (Task invocation parameter: COMMIT_SHA)

# Positive test: valid input should produce no deny violations.
test_task_invocation_parameters_commit_sha_check_valid if {
	count(task_invocation_parameters_commit_sha_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"invocation": {
							"parameters": {
								"COMMIT_SHA": "356a767377f0917039b096677333b16bb6c8fbbb",
							},
						},
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_invocation_parameters_commit_sha_check_invalid if {
	count(task_invocation_parameters_commit_sha_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"invocation": {
							"parameters": {},
						},
					},
				],
			},
		},
	}
}
