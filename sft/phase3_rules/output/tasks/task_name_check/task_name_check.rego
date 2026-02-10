package task_name_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	task.name != "init"
	msg := sprintf("name is %v, expected init", [task.name])
}

