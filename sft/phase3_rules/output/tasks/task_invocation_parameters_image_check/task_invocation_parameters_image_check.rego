package task_invocation_parameters_image_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	not task.invocation.parameters.IMAGE
	msg := "IMAGE is missing"
}

