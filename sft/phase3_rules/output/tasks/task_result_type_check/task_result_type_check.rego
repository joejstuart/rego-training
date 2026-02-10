package task_result_type_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	some result in task.results
	result.type != "string"
	msg := sprintf("type is %v, expected string", [result.type])
}

