package all_subjects_have_name

import rego.v1

deny contains msg if {
	some subject in input.subject
	not subject.name
	msg := "subject is missing name field"
}
