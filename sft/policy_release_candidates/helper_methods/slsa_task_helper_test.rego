package slsa_task_helper_test

import data.slsa_task_helper
import rego.v1

test_passes_through_v02_task if {
	task := {"ref": {"kind": "task", "name": "buildah"}, "results": []}
	slsa_task_helper.slsa_task(task) == task
}

test_merges_status_results_for_v1_taskrun_task if {
	task := {
		"taskRef": {"kind": "task", "name": "buildah"},
		"status": {"results": [{"name": "IMAGE_URL", "value": "quay.io/acme/app"}]},
	}
	out := slsa_task_helper.slsa_task(task)
	count(out.results) == 1
}
