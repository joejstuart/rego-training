package subjects_match_build_results

import rego.v1

deny contains msg if {
	some subject in input.subject
	digest := subject.digest.sha256
	not _digest_in_results(digest)
	msg := sprintf("subject digest %v not found in any task IMAGE_DIGEST result", [digest])
}

_digest_in_results(digest) if {
	some task in input.predicate.buildConfig.tasks
	some result in task.results
	result.name == "IMAGE_DIGEST"
	result.value == sprintf("sha256:%s", [digest])
}
