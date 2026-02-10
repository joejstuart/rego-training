package task_step_environment_image_check_test

import rego.v1

import data.task_step_environment_image_check

# Instruction: Write a Rego deny rule that rejects the attestation if `.predicate.buildConfig.tasks[*].steps[*].environment.image` is not `"oci://registry.access.redhat.com/ubi9/skopeo@sha256:75c6ac42431e29465eba3ff3367a18416722cdc18cb7c5745b448f199082fdef"`. (Task step field: image)

# Positive test: valid input should produce no deny violations.
test_task_step_environment_image_check_valid if {
	count(task_step_environment_image_check.deny) == 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"steps": [
							{
								"environment": {
									"image": "oci://registry.access.redhat.com/ubi9/skopeo@sha256:75c6ac42431e29465eba3ff3367a18416722cdc18cb7c5745b448f199082fdef",
								},
							},
						],
					},
				],
			},
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_task_step_environment_image_check_invalid if {
	count(task_step_environment_image_check.deny) > 0
	with input as {
		"predicate": {
			"buildConfig": {
				"tasks": [
					{
						"steps": [
							{
								"environment": {
									"image": "oci://example.com/INVALID",
								},
							},
						],
					},
				],
			},
		},
	}
}
