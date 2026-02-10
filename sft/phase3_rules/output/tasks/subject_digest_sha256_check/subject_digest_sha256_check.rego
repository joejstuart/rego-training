package subject_digest_sha256_check

import rego.v1

deny contains msg if {
	some subject in input.subject
	not subject.digest.sha256
	msg := "sha256 is missing"
}

