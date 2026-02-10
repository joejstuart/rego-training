package git_revision_matches_material_test

import rego.v1

import data.git_revision_matches_material

# Instruction: Write a Rego deny rule that rejects the attestation if the git commit SHA in `.predicate.invocation.parameters.revision` does not match the `digest.sha1` of the git material in `.predicate.materials` (the entry whose `uri` starts with `"git+"`). This ensures the build was performed on the declared source revision.

# Positive test: valid input should produce no deny violations.
test_git_revision_matches_material_valid if {
	count(git_revision_matches_material.deny) == 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {
					"revision": "356a767377f0917039b096677333b16bb6c8fbbb",
				},
			},
			"materials": [
				{
					"uri": "oci://quay.io/example/image",
					"digest": {
						"sha256": "abc123",
					},
				},
				{
					"uri": "git+https://github.com/example/repo.git",
					"digest": {
						"sha1": "356a767377f0917039b096677333b16bb6c8fbbb",
					},
				},
			],
		},
	}
}

# Negative test: invalid input should produce at least one deny violation.
test_git_revision_matches_material_invalid if {
	count(git_revision_matches_material.deny) > 0
	with input as {
		"predicate": {
			"invocation": {
				"parameters": {
					"revision": "356a767377f0917039b096677333b16bb6c8fbbb",
				},
			},
			"materials": [
				{
					"uri": "oci://quay.io/example/image",
					"digest": {
						"sha256": "abc123",
					},
				},
				{
					"uri": "git+https://github.com/example/repo.git",
					"digest": {
						"sha1": "different_sha_mismatch",
					},
				},
			],
		},
	}
}
