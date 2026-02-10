package task_finished_on_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	not task.finishedOn
	msg := "finishedOn is missing"
}

