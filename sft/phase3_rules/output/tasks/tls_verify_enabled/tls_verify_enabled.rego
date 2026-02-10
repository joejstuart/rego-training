package tls_verify_enabled

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	task.invocation.parameters.TLSVERIFY
	task.invocation.parameters.TLSVERIFY != "true"
	msg := sprintf("task %v has TLSVERIFY=%v, must be true", [task.name, task.invocation.parameters.TLSVERIFY])
}
