package task_step_environment_image_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	some step in task.steps
	step.environment.image != "oci://registry.access.redhat.com/ubi9/skopeo@sha256:75c6ac42431e29465eba3ff3367a18416722cdc18cb7c5745b448f199082fdef"
	msg := sprintf("image is %v, expected oci://registry.access.redhat.com/ubi9/skopeo@sha256:75c6ac42431e29465eba3ff3367a18416722cdc18cb7c5745b448f199082fdef", [step.environment.image])
}

