package provenance_materials_candidate_test

import data.provenance_materials_candidate
import rego.v1

test_deny_when_git_clone_task_not_found if {
	input_data := {"attestations": [attestation_with_task_and_material(other_task, [])]}
	count(provenance_materials_candidate.deny) > 0 with input as input_data
}

test_deny_when_material_entry_does_not_match_git_clone_output if {
	task := git_clone_task("https://github.com/acme/repo", "abc123")
	materials := [{"uri": "git+https://github.com/acme/other.git", "digest": {"sha1": "abc123"}}]
	input_data := {"attestations": [attestation_with_task_and_material(task, materials)]}
	count(provenance_materials_candidate.deny) > 0 with input as input_data
}

test_allow_when_material_matches_git_clone_output if {
	task := git_clone_task("https://github.com/acme/repo", "abc123")
	materials := [{"uri": "git+https://github.com/acme/repo.git", "digest": {"sha1": "abc123"}}]
	input_data := {"attestations": [attestation_with_task_and_material(task, materials)]}
	count(provenance_materials_candidate.deny) == 0 with input as input_data
}

attestation_with_task_and_material(task, materials) := {
	"statement": {
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": "tekton.dev/v1/PipelineRun",
			"materials": materials,
			"buildConfig": {"tasks": [task]},
		},
	},
}

git_clone_task(url, commit) := {
	"ref": {"kind": "task", "name": "git-clone"},
	"invocation": {"parameters": {}},
	"results": [
		{"name": "url", "value": url},
		{"name": "commit", "value": commit},
	],
}

other_task := {
	"ref": {"kind": "task", "name": "buildah"},
	"invocation": {"parameters": {}},
	"results": [{"name": "IMAGE_URL", "value": "quay.io/acme/app"}],
}
