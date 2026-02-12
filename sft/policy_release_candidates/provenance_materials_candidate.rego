package provenance_materials_candidate

import rego.v1

deny contains msg if {
	some attestation in pipelinerun_attestations
	count(git_clone_tasks(attestation)) == 0
	msg := "Task git-clone not found"
}

deny contains msg if {
	some attestation in pipelinerun_attestations
	some task in git_clone_tasks(attestation)
	url := normalize_git_url(task_result(task, "url"))
	commit := task_result(task, "commit")

	materials := [m |
		some m in attestation.statement.predicate.materials
		m.uri == url
		m.digest.sha1 == commit
	]
	count(materials) == 0
	msg := sprintf(
		"Entry in materials for the git repo %q and commit %q not found",
		[url, commit],
	)
}

normalize_git_url(url) := suffix_git_url(prefix_git_url(url))

prefix_git_url(url) := normalized if {
	not strings.any_prefix_match(url, "git+")
	normalized := sprintf("git+%s", [url])
} else := url

suffix_git_url(url) := normalized if {
	not strings.any_suffix_match(url, ".git")
	normalized := sprintf("%s.git", [url])
} else := url

git_clone_tasks(attestation) := [task |
	some task in tasks(attestation)
	commit := task_result(task, "commit")
	count(trim_space(commit)) > 0
	url := task_result(task, "url")
	count(trim_space(url)) > 0
]

task_result(task, name) := value if {
	some result in task_results(task)
	result_name := object.get(result, "name", "")
	result_name == name
	value := object.get(result, "value", "")
}

task_results(task) := task.results

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
