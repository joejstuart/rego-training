package task_invocation_parameters_tlsverify_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	task.invocation.parameters.TLSVERIFY != "true"
	msg := sprintf("TLSVERIFY is %v, expected true", [task.invocation.parameters.TLSVERIFY])
}

