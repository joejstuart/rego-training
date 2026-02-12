# regal ignore:external-reference
# regal ignore:leaked-internal-reference
# regal ignore:rule-length
# regal ignore:file-length
package slsa_task_helper

import rego.v1

slsa_task(task) := task if {
	not task.status.results
	ref := task_ref(task)
	ref.kind == "task"
}

slsa_task(task) := merged if {
	task.status.results
	ref := task_ref(task)
	ref.kind == "task"
	merged := object.union(task, {"results": task.status.results})
}

task_ref(task) := r if {
	r := task.ref
} else := r if {
	r := task.taskRef
} else := r if {
	r := task.spec.taskRef
}
