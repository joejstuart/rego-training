package task_started_on_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	not task.startedOn
	msg := "startedOn is missing"
}

