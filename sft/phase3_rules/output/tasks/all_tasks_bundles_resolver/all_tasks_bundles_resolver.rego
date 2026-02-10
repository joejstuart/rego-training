package all_tasks_bundles_resolver

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	task.ref.resolver != "bundles"
	msg := sprintf("task %v uses resolver %v, expected bundles", [task.name, task.ref.resolver])
}
