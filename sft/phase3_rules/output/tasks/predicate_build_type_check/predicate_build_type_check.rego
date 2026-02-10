package predicate_build_type_check

import rego.v1

deny contains msg if {
	input.predicate.buildType != "tekton.dev/v1beta1/PipelineRun"
	msg := sprintf("buildType is %v, expected tekton.dev/v1beta1/PipelineRun", [input.predicate.buildType])
}

