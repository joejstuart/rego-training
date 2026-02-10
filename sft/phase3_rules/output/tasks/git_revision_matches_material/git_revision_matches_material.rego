package git_revision_matches_material

import rego.v1

deny contains msg if {
	revision := input.predicate.invocation.parameters.revision
	some material in input.predicate.materials
	startswith(material.uri, "git+")
	material.digest.sha1 != revision
	msg := sprintf("git material sha1 %v does not match revision %v", [material.digest.sha1, revision])
}
