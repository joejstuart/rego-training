package all_tasks_have_service_account

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	not task.serviceAccountName
	msg := "task is missing serviceAccountName"
}

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	task.serviceAccountName == ""
	msg := sprintf("task %v has empty serviceAccountName", [task.name])
}
