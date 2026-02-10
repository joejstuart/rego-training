package task_step_environment_container_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	some step in task.steps
	step.environment.container != "init"
	msg := sprintf("container is %v, expected init", [step.environment.container])
}

