package trusted_builder_id

import rego.v1

deny contains msg if {
	input.predicate.builder.id != "https://tekton.dev/chains/v2"
	msg := sprintf("untrusted builder.id: %v", [input.predicate.builder.id])
}

deny contains msg if {
	input.predicate.buildType != "tekton.dev/v1beta1/PipelineRun"
	msg := sprintf("unexpected buildType: %v", [input.predicate.buildType])
}
