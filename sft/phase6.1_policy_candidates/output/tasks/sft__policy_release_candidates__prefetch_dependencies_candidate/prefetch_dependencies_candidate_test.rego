package prefetch_dependencies_candidate_test

import data.prefetch_dependencies_candidate
import rego.v1

test_deny_when_prefetch_dependencies_mode_is_permissive if {
	input_data := {"attestations": [attestation_with_tasks([prefetch_task("permissive")])]}
	count(prefetch_dependencies_candidate.deny) > 0 with input as input_data
}

test_allow_when_prefetch_dependencies_mode_is_not_permissive if {
	input_data := {"attestations": [attestation_with_tasks([prefetch_task("strict")])]}
	count(prefetch_dependencies_candidate.deny) == 0 with input as input_data
}

test_allow_when_prefetch_task_not_present if {
	input_data := {"attestations": [attestation_with_tasks([other_task])]}
	count(prefetch_dependencies_candidate.deny) == 0 with input as input_data
}

attestation_with_tasks(tasks) := {"statement": {
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": "tekton.dev/v1/PipelineRun",
		"buildConfig": {"tasks": tasks},
	},
}}

prefetch_task(mode) := {
	"ref": {"kind": "task", "name": "prefetch-dependencies"},
	"invocation": {"parameters": {"mode": mode}},
	"results": [],
}

other_task := {
	"ref": {"kind": "task", "name": "buildah"},
	"invocation": {"parameters": {"mode": "permissive"}},
	"results": [],
}
