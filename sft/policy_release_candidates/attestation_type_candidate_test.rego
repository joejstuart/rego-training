package attestation_type_candidate_test

import data.attestation_type_candidate
import rego.v1

test_deny_when_no_pipelinerun_attestation if {
	input_data := {"attestations": []}
	count(attestation_type_candidate.deny) > 0 with input as input_data
}

test_deny_when_unknown_attestation_type if {
	input_data := {"attestations": [v02_attestation("https://example.com/unknown")]}
	count(attestation_type_candidate.deny) > 0 with input as input_data
}

test_allow_when_known_attestation_type if {
	input_data := {"attestations": [v02_attestation("https://in-toto.io/Statement/v1")]}
	count(attestation_type_candidate.deny) == 0 with input as input_data
}

v02_attestation(att_type) := {
	"statement": {
		"_type": att_type,
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": "tekton.dev/v1/PipelineRun",
		},
	},
}
