package build_tasks_have_image_digest_result_test

import rego.v1

import data.build_tasks_have_image_digest_result

# Instruction: Write a Rego deny rule that rejects the attestation if any task whose name starts with `"build-container"` does not have a result named `"IMAGE_DIGEST"`.

# Positive test: valid input should produce no deny violations.
test_build_tasks_have_image_digest_result_valid if {
	count(build_tasks_have_image_digest_result.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build-container-amd64",
						"results": [
							{
								"name": "IMAGE_DIGEST",
								"type": "string",
								"value": "sha256:abc",
							},
							{
								"name": "IMAGE_URL",
								"type": "string",
								"value": "quay.io/ex",
							},
						],
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_build_tasks_have_image_digest_result_invalid if {
	count(build_tasks_have_image_digest_result.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"name": "build-container-amd64",
						"results": [
							{
								"name": "IMAGE_DIGEST",
								"type": "string",
								"value": "sha256:abc",
							},
							{
								"name": "IMAGE_URL",
								"type": "string",
								"value": "quay.io/ex",
							},
						],
					},
					{
						"name": "build-container-arm64",
						"results": [
							{
								"name": "IMAGE_URL",
								"type": "string",
								"value": "quay.io/ex",
							},
						],
					},
				],
			},
		},
	}
}
