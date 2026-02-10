package all_tasks_succeeded

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	task.status != "Succeeded"
	msg := sprintf("task %v has status %v, expected Succeeded", [task.name, task.status])
}
