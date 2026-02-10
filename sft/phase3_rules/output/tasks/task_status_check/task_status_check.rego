package task_status_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	task.status != "Succeeded"
	msg := sprintf("status is %v, expected Succeeded", [task.status])
}

