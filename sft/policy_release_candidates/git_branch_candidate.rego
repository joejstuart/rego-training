package git_branch_candidate

import rego.v1

deny contains msg if {
	some task in tasks_from_pipelinerun
	branch := task.invocation.environment.annotations["build.appstudio.redhat.com/target_branch"]
	not matches_any(branch)
	msg := sprintf(
		"Build target is %s which is not a trusted target branch",
		[branch],
	)
}

matches_any(branch) if {
	some pattern in allowed_target_branch_patterns
	regex.match(pattern, branch)
}

allowed_target_branch_patterns := [
	"^main$",
	"^release-.*$",
	"^rhel-.*$",
]

tasks_from_pipelinerun := [task |
	some att in pipelinerun_attestations
	some task in tasks(att)
]

tasks(attestation) := {task |
	some maybe_task in _maybe_tasks(attestation)
	task := _slsa_task(maybe_task)
}

_maybe_tasks(attestation) := attestation.statement.predicate.buildConfig.tasks if {
	attestation.statement.predicateType == "https://slsa.dev/provenance/v0.2"
}

_maybe_tasks(attestation) := extracted if {
	attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
	resolved_deps := attestation.statement.predicate.buildDefinition.resolvedDependencies
	extracted := [task |
		some dep in resolved_deps
		dep.name == "pipelineTask"
		dep.content
		task := json.unmarshal(base64.decode(dep.content))
	]
}

_slsa_task(task) := task if {
	not task.status.results
	ref := task_ref(task)
	ref.kind == "task"
} else := merged if {
	task.status.results
	ref := task_ref(task)
	ref.kind == "task"
	merged := object.union(task, {"results": task.status.results})
}

task_ref(task) := r if {
	r := task.ref
} else := r if {
	r := task.taskRef
} else := r if {
	r := task.spec.taskRef
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
