package image_digest_requires_succeeded

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	_has_image_digest(task)
	task.status != "Succeeded"
	msg := sprintf("task %v produces IMAGE_DIGEST but has status %v", [task.name, task.status])
}

_has_image_digest(task) if {
	some result in task.results
	result.name == "IMAGE_DIGEST"
}
