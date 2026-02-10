package task_ref_params_value_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	some param in task.ref.params
	param.value != "init"
	msg := sprintf("value is %v, expected init", [param.value])
}

