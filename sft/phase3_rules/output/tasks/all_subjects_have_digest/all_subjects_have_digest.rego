package all_subjects_have_digest

import rego.v1

deny contains msg if {
	some subject in input.subject
	not subject.digest.sha256
	msg := "subject is missing digest.sha256"
}
