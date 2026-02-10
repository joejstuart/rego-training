package build_tasks_have_image_digest_result

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	startswith(task.name, "build-container")
	not _has_result(task, "IMAGE_DIGEST")
	msg := sprintf("build task %v is missing IMAGE_DIGEST result", [task.name])
}

_has_result(task, name) if {
	some result in task.results
	result.name == name
}
