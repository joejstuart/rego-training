package all_task_refs_have_required_params_test

import rego.v1

import data.all_task_refs_have_required_params

# Instruction: Write a Rego deny rule that rejects the attestation if any task's `.ref.params` does not include all three required parameter names: `"name"`, `"bundle"`, and `"kind"`.

# Positive test: valid input should produce no deny violations.
test_all_task_refs_have_required_params_valid if {
	count(all_task_refs_have_required_params.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build",
						"ref": {
							"resolver": "bundles",
							"params": [
								{
									"name": "name",
									"value": "buildah",
								},
								{
									"name": "bundle",
									"value": "quay.io/example/task@sha256:abc",
								},
								{
									"name": "kind",
									"value": "task",
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
test_all_task_refs_have_required_params_invalid if {
	count(all_task_refs_have_required_params.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build",
						"ref": {
							"resolver": "bundles",
							"params": [
								{
									"name": "name",
									"value": "buildah",
								},
								{
									"name": "bundle",
									"value": "quay.io/example/task@sha256:abc",
								},
								{
									"name": "kind",
									"value": "task",
								},
							],
						},
					},
					{
						"name": "test",
						"ref": {
							"resolver": "bundles",
							"params": [
								{
									"name": "name",
									"value": "test-task",
								},
							],
						},
					},
				],
			},
		},
	}
}
