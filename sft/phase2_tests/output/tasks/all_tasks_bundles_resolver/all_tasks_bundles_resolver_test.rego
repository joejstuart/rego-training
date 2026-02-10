package all_tasks_bundles_resolver_test

import rego.v1

import data.all_tasks_bundles_resolver

# Instruction: Write a Rego deny rule that rejects the attestation if any task in `.predicate.buildConfig.tasks` does not use `"bundles"` as its `.ref.resolver`.

# Positive test: valid input should produce no deny violations.
test_all_tasks_bundles_resolver_valid if {
	count(all_tasks_bundles_resolver.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build",
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
test_all_tasks_bundles_resolver_invalid if {
	count(all_tasks_bundles_resolver.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build",
						"ref": {
							"resolver": "bundles",
						},
					},
					{
						"name": "test",
						"ref": {
							"resolver": "git",
						},
					},
				],
			},
		},
	}
}
