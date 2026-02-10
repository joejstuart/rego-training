package scan_tasks_have_test_output

import rego.v1

deny contains msg if {
	some task in input.predicate.buildConfig.tasks
	_is_scan_task(task)
	not _has_result(task, "TEST_OUTPUT")
	msg := sprintf("scan task %v is missing TEST_OUTPUT result", [task.name])
}

_is_scan_task(task) if contains(task.name, "scan")

_is_scan_task(task) if contains(task.name, "sast")

_has_result(task, name) if {
	some result in task.results
	result.name == name
}
