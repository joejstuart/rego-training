package task_result_value_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	some result in task.results
	result.value != "true"
	msg := sprintf("value is %v, expected true", [result.value])
}

