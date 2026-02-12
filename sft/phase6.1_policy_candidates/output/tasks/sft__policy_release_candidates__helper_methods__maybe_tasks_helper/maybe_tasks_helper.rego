# regal ignore:external-reference
# regal ignore:leaked-internal-reference
# regal ignore:rule-length
# regal ignore:file-length
package maybe_tasks_helper

import rego.v1

maybe_tasks(attestation) := attestation.statement.predicate.buildConfig.tasks if {
	attestation.statement.predicateType == "https://slsa.dev/provenance/v0.2"
}

maybe_tasks(attestation) := extracted if {
	attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
	resolved_deps := attestation.statement.predicate.buildDefinition.resolvedDependencies
	extracted := [task |
		some dep in resolved_deps
		dep.name == "pipelineTask"
		dep.content
		task := json.unmarshal(base64.decode(dep.content))
	]
}
