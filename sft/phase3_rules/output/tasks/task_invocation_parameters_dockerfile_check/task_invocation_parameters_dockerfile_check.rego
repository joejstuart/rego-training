package task_invocation_parameters_dockerfile_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	task.invocation.parameters.DOCKERFILE != "Containerfile"
	msg := sprintf("DOCKERFILE is %v, expected Containerfile", [task.invocation.parameters.DOCKERFILE])
}

