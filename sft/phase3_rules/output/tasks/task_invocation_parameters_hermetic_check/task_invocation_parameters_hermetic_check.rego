package task_invocation_parameters_hermetic_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	task.invocation.parameters.HERMETIC != "true"
	msg := sprintf("HERMETIC is %v, expected true", [task.invocation.parameters.HERMETIC])
}

