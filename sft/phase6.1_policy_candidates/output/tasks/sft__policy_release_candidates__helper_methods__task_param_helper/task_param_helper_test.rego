package task_param_helper_test

import data.task_param_helper
import rego.v1

test_reads_invocation_parameters_map if {
	task := {"invocation": {"parameters": {"mode": "strict"}}}
	task_param_helper.task_param(task, "mode") == "strict"
}

test_reads_pipeline_definition_params_array if {
	task := {
		"params": [{"name": "mode", "value": "permissive"}],
		"invocation": {"parameters": {}},
	}
	task_param_helper.task_param(task, "mode") == "permissive"
}
