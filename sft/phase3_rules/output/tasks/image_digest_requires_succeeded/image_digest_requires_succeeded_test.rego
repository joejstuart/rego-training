package image_digest_requires_succeeded_test

import rego.v1

import data.image_digest_requires_succeeded

# Instruction: Write a Rego deny rule that rejects the attestation if any task that produces an `IMAGE_DIGEST` result did not complete with status `"Succeeded"`. The rule should iterate over all tasks, check if a result named `"IMAGE_DIGEST"` exists, and if so, verify the task's `status` is `"Succeeded"`.

# Positive test: valid input should produce no deny violations.
test_image_digest_requires_succeeded_valid if {
	count(image_digest_requires_succeeded.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build-container-amd64",
						"status": "Succeeded",
						"results": [
							{
								"name": "IMAGE_DIGEST",
								"type": "string",
								"value": "sha256:abc123",
							},
						],
					},
					{
						"name": "build-container-arm64",
						"status": "Succeeded",
						"results": [
							{
								"name": "IMAGE_DIGEST",
								"type": "string",
								"value": "sha256:def456",
							},
						],
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_image_digest_requires_succeeded_invalid if {
	count(image_digest_requires_succeeded.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build-container-amd64",
						"status": "Succeeded",
						"results": [
							{
								"name": "IMAGE_DIGEST",
								"type": "string",
								"value": "sha256:abc123",
							},
						],
					},
					{
						"name": "build-container-arm64",
						"status": "Failed",
						"results": [
							{
								"name": "IMAGE_DIGEST",
								"type": "string",
								"value": "sha256:def456",
							},
						],
					},
				],
			},
		},
	}
}
