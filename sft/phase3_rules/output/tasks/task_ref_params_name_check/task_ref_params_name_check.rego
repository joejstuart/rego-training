package task_ref_params_name_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	some param in task.ref.params
	param.name != "name"
	msg := sprintf("name is %v, expected name", [param.name])
}

