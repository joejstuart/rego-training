package task_steps_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	not task.steps
	msg := "steps is missing"
}

