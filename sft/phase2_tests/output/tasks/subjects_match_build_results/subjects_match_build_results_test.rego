package subjects_match_build_results_test

import rego.v1

import data.subjects_match_build_results

# Instruction: Write a Rego deny rule that rejects the attestation if any subject's `digest.sha256` does not appear as an `IMAGE_DIGEST` result value in any task under `.predicate.buildConfig.tasks`. This ensures every attested image was actually produced by a task in the pipeline.

# Positive test: valid input should produce no deny violations.
test_subjects_match_build_results_valid if {
	count(subjects_match_build_results.deny) == 0
	with input as {
		"subject": [
			{
				"name": "quay.io/example/image",
				"digest": {
					"sha256": "abc123",
				},
			},
		],
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build-container",
						"results": [
							{
								"name": "IMAGE_DIGEST",
								"type": "string",
								"value": "sha256:abc123",
							},
						],
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_subjects_match_build_results_invalid if {
	count(subjects_match_build_results.deny) > 0
	with input as {
		"subject": [
			{
				"name": "quay.io/example/image",
				"digest": {
					"sha256": "abc123",
				},
			},
			{
				"name": "quay.io/example/image2",
				"digest": {
					"sha256": "orphan999",
				},
			},
		],
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build-container",
						"results": [
							{
								"name": "IMAGE_DIGEST",
								"type": "string",
								"value": "sha256:abc123",
							},
						],
					},
				],
			},
		},
	}
}
