package all_tasks_have_timestamps

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	not task.startedOn
	msg := sprintf("task %v is missing startedOn", [task.name])
}

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	not task.finishedOn
	msg := sprintf("task %v is missing finishedOn", [task.name])
}
