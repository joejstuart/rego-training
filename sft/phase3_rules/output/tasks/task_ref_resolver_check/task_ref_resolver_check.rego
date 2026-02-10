package task_ref_resolver_check

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	task.ref.resolver != "bundles"
	msg := sprintf("resolver is %v, expected bundles", [task.ref.resolver])
}

