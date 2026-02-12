package hermetic_task_candidate

import rego.v1

deny contains msg if {
	some task in not_hermetic_tasks
	msg := sprintf(
		"Task %q was not invoked with the hermetic parameter set",
		[task_name(task)],
	)
}

not_hermetic_tasks contains task if {
	some required_name in required_hermetic_tasks
	some attestation in pipelinerun_attestations
	some task in tasks(attestation)
	task_name(task) == required_name
	not task_is_hermetic(task)
}

task_is_hermetic(task) if {
	task_param(task, "HERMETIC") == "true"
}

required_hermetic_tasks := {
	"buildah",
	"prefetch-dependencies",
}

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

task_name(task) := task_ref(task).name

task_params(task) := task.invocation.parameters if {
	not task.params
} else := task.invocation.parameters if {
	task.params
	count(task.params) == 0
} else := params if {
	task.params
	count(task.params) > 0
	params := {param.name: param.value |
		some param in task.params
	}
}

task_param(task, name) := task_params(task)[name]

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
