package all_task_refs_have_required_params

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	param_names := {p.name | some p in task.ref.params}
	required := {"name", "bundle", "kind"}
	missing := required - param_names
	count(missing) > 0
	msg := sprintf("task %v is missing required ref params: %v", [task.name, missing])
}
