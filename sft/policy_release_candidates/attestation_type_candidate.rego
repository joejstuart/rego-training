package attestation_type_candidate

import rego.v1

deny contains msg if {
	count(pipelinerun_attestations) == 0
	msg := "Missing pipelinerun attestation"
}

deny contains msg if {
	some att in pipelinerun_attestations
	not att.statement._type in known_attestation_types
	msg := sprintf("Unknown attestation type %q", [att.statement._type])
}

known_attestation_types := {
	"https://in-toto.io/Statement/v0.1",
	"https://in-toto.io/Statement/v1",
}

pipelinerun_attestations := [att |
	some att in input.attestations
	_is_pipelinerun_attestation(att)
]

_is_pipelinerun_attestation(att) if {
	att.statement.predicateType == "https://slsa.dev/provenance/v0.2"
	att.statement.predicate.buildType in {
		"tekton.dev/v1/PipelineRun",
		"tekton.dev/v1beta1/PipelineRun",
		"https://tekton.dev/attestations/chains/pipelinerun@v2",
	}
}

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
