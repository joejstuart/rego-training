package hermetic_task_candidate_test

import data.hermetic_task_candidate
import rego.v1

test_deny_when_required_task_missing_hermetic_param if {
	tasks := [task("buildah", "false"), task("prefetch-dependencies", "true")]
	input_data := {"attestations": [attestation_with_tasks(tasks)]}
	count(hermetic_task_candidate.deny) > 0 with input as input_data
}

test_allow_when_required_tasks_are_hermetic if {
	tasks := [task("buildah", "true"), task("prefetch-dependencies", "true")]
	input_data := {"attestations": [attestation_with_tasks(tasks)]}
	count(hermetic_task_candidate.deny) == 0 with input as input_data
}

attestation_with_tasks(tasks) := {"statement": {
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": "tekton.dev/v1/PipelineRun",
		"buildConfig": {"tasks": tasks},
	},
}}

task(name, hermetic) := {
	"ref": {"kind": "task", "name": name},
	"invocation": {"parameters": {"HERMETIC": hermetic}},
	"results": [],
}
