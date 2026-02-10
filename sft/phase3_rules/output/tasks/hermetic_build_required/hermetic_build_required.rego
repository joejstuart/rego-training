package hermetic_build_required

import rego.v1

deny contains msg if {
	input.predicate.invocation.parameters.hermetic != "true"
	msg := "build is not hermetic at pipeline level"
}

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	startswith(task.name, "build-container")
	task.invocation.parameters.HERMETIC != "true"
	msg := sprintf("task %v has HERMETIC=%v, expected true", [task.name, task.invocation.parameters.HERMETIC])
}
