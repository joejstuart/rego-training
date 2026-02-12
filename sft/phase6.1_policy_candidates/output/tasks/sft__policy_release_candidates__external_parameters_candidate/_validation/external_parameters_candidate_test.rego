package external_parameters_candidate_test

import data.external_parameters_candidate
import rego.v1

test_deny_when_params_do_not_match_expected_set if {
	att := v1_attestation(
		[
			{"name": "git-revision", "value": "abc123"},
			{"name": "output-image", "value": "quay.io/org/app:latest"},
		],
		[],
	)
	input_data := {"attestations": [att]}
	count(external_parameters_candidate.deny) > 0 with input as input_data
}

test_deny_when_shared_workspace_is_used if {
	att := v1_attestation(
		[
			{"name": "git-repo", "value": "https://github.com/org/repo"},
			{"name": "git-revision", "value": "abc123"},
			{"name": "output-image", "value": "quay.io/org/app@sha256:deadbeef"},
		],
		[{"persistentVolumeClaim": {"claimName": "my-pvc"}}],
	)
	input_data := {"attestations": [att]}
	count(external_parameters_candidate.deny) > 0 with input as input_data
}

test_allow_when_expected_params_and_no_shared_workspace if {
	att := v1_attestation(
		[
			{"name": "git-repo", "value": "https://github.com/org/repo"},
			{"name": "git-revision", "value": "abc123"},
			{"name": "output-image", "value": "quay.io/org/app@sha256:deadbeef"},
		],
		[],
	)
	input_data := {"attestations": [att]}
	count(external_parameters_candidate.deny) == 0 with input as input_data
}

v1_attestation(params, workspaces) := {"statement": {
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {"buildDefinition": {
		"buildType": "https://tekton.dev/chains/v2/slsa",
		"externalParameters": {"runSpec": {
			"pipelineRef": {"name": "example"},
			"params": params,
			"workspaces": workspaces,
		}},
	}},
}}
