package all_tasks_have_steps

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	not task.steps
	msg := sprintf("task %v is missing steps", [task.name])
}

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	task.steps
	count(task.steps) == 0
	msg := sprintf("task %v has empty steps", [task.name])
}
