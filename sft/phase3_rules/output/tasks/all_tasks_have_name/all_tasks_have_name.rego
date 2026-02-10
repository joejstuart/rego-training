package all_tasks_have_name

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	not task.name
	msg := "task is missing name field"
}
