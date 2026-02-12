# regal ignore:external-reference
# regal ignore:leaked-internal-reference
# regal ignore:rule-length
# regal ignore:file-length
package task_names_helper

import rego.v1

task_name(task) := task_ref(task).name

task_names(task) := names if {
	raw_name := task_name(task)
	name := split(raw_name, "[")[0]
	params := {n |
		some k, v in task_params(task)
		n := sprintf("%s[%s=%s]", [name, k, v])
	}
	names := {name} | params
}

task_params(task) := task.invocation.parameters if {
	not task.params
}

task_params(task) := task.invocation.parameters if {
	task.params
	count(task.params) == 0
}

task_params(task) := params if {
	task.params
	count(task.params) > 0
	params := {param.name: param.value |
		some param in task.params
	}
}

task_ref(task) := r if {
	r := task.ref
} else := r if {
	r := task.taskRef
} else := r if {
	r := task.spec.taskRef
}
