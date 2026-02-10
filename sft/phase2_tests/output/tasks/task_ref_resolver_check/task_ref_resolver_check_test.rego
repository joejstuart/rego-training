package task_ref_resolver_check_test

import rego.v1

import data.task_ref_resolver_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].ref.resolver` is not `"bundles"`. (Task reference field: resolver)

# Positive test: valid input should produce no deny violations.
test_task_ref_resolver_check_valid if {
	count(task_ref_resolver_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"ref": {
							"resolver": "bundles",
						},
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_ref_resolver_check_invalid if {
	count(task_ref_resolver_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"ref": {
							"resolver": "INVALID_VALUE",
						},
					},
				],
			},
		},
	}
}
