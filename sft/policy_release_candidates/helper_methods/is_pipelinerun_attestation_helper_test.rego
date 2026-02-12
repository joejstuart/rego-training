package is_pipelinerun_attestation_helper_test

import data.is_pipelinerun_attestation_helper
import rego.v1

test_true_for_v02_pipelinerun if {
	att := {
		"statement": {
			"predicateType": "https://slsa.dev/provenance/v0.2",
			"predicate": {"buildType": "tekton.dev/v1/PipelineRun"},
		},
	}
	is_pipelinerun_attestation_helper.is_pipelinerun_attestation(att)
}

test_true_for_v1_pipelinerun if {
	att := {
		"statement": {
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate": {
				"buildDefinition": {
					"buildType": "https://tekton.dev/chains/v2/slsa",
					"externalParameters": {"runSpec": {"pipelineRef": {"name": "x"}}},
				},
			},
		},
	}
	is_pipelinerun_attestation_helper.is_pipelinerun_attestation(att)
}

test_false_for_taskrun_build_type if {
	att := {
		"statement": {
			"predicateType": "https://slsa.dev/provenance/v0.2",
			"predicate": {"buildType": "tekton.dev/v1/TaskRun"},
		},
	}
	not is_pipelinerun_attestation_helper.is_pipelinerun_attestation(att)
}
