package task_invocation_parameters_commit_sha_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	not task.invocation.parameters.COMMIT_SHA
	msg := "COMMIT_SHA is missing"
}

