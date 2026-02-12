package git_branch_candidate_test

import data.git_branch_candidate
import rego.v1

test_deny_when_branch_is_untrusted if {
	input_data := {"attestations": [attestation_with_branch("feature/foo")]}
	count(git_branch_candidate.deny) > 0 with input as input_data
}

test_allow_when_branch_matches_allowed_pattern if {
	input_data := {"attestations": [attestation_with_branch("main")]}
	count(git_branch_candidate.deny) == 0 with input as input_data
}

attestation_with_branch(branch) := {"statement": {
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": "tekton.dev/v1/PipelineRun",
		"buildConfig": {"tasks": [{
			"ref": {"kind": "task", "name": "buildah"},
			"invocation": {
				"parameters": {},
				"environment": {"annotations": {"build.appstudio.redhat.com/target_branch": branch}},
			},
			"results": [],
		}]},
	},
}}
