package task_names_helper_test

import data.task_names_helper
import rego.v1

test_returns_base_and_parameterized_task_names if {
	task := {
		"ref": {"kind": "task", "name": "prefetch-dependencies"},
		"invocation": {"parameters": {"mode": "permissive"}},
	}
	names := task_names_helper.task_names(task)
	"prefetch-dependencies" in names
	"prefetch-dependencies[mode=permissive]" in names
}
