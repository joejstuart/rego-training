# regal ignore:external-reference
# regal ignore:leaked-internal-reference
# regal ignore:rule-length
# regal ignore:file-length
package external_parameters_candidate

import rego.v1

deny contains msg if {
	some provenance in pipelinerun_attestations
	param_names := {p.name |
		some p in provenance.statement.predicate.buildDefinition.externalParameters.runSpec.params
		p.value != ""
	}
	expected_names := {"git-repo", "git-revision", "output-image"}
	expected_names != param_names
	msg := sprintf(
		"PipelineRun params, %v, do not match expectation, %v.",
		[param_names, expected_names],
	)
}

deny contains msg if {
	some provenance in pipelinerun_attestations
	shared_workspaces := {w |
		some w in provenance.statement.predicate.buildDefinition.externalParameters.runSpec.workspaces
		w.persistentVolumeClaim
	}
	count(shared_workspaces) > 0
	msg := sprintf("PipelineRun uses shared volumes, %v.", [shared_workspaces])
}

pipelinerun_attestations := [att |
	some att in input.attestations
	_is_pipelinerun_attestation(att)
]

_is_pipelinerun_attestation(att) if {
	att.statement.predicateType == "https://slsa.dev/provenance/v1"
	att.statement.predicate.buildDefinition.buildType in {
		"https://tekton.dev/chains/v2/slsa",
		"https://tekton.dev/chains/v2/slsa-tekton",
	}
	spec_keys := object.keys(att.statement.predicate.buildDefinition.externalParameters.runSpec)
	pipeline_keys := {"pipelineRef", "pipelineSpec"}
	count(pipeline_keys - spec_keys) != count(pipeline_keys)
}
