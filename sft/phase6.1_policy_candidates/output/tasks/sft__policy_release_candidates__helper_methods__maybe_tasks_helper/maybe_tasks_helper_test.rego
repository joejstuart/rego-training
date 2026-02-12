package maybe_tasks_helper_test

import data.maybe_tasks_helper
import rego.v1

test_returns_build_config_tasks_for_v02 if {
	tasks := [{"ref": {"kind": "task", "name": "buildah"}}]
	att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {"buildConfig": {"tasks": tasks}},
	}}
	maybe_tasks_helper.maybe_tasks(att) == tasks
}

test_decodes_resolved_dependencies_for_v1 if {
	task_obj := {"taskRef": {"kind": "task", "name": "buildah"}}
	encoded := base64.encode(json.marshal(task_obj))
	att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {"resolvedDependencies": [{"name": "pipelineTask", "content": encoded}]}},
	}}
	maybe_tasks_helper.maybe_tasks(att) == [task_obj]
}
