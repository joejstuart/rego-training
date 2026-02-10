package task_results_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	not task.results
	msg := "results is missing"
}

