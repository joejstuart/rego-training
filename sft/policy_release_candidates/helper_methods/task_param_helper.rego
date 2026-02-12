package task_param_helper

import rego.v1

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

task_param(task, name) := task_params(task)[name]
