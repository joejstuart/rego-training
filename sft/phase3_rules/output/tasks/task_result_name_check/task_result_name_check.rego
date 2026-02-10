package task_result_name_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	some result in task.results
	result.name != "build"
	msg := sprintf("name is %v, expected build", [result.name])
}

