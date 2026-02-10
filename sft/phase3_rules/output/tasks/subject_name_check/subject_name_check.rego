package subject_name_check

import rego.v1

deny contains msg if {
	some subject in input.subject
	not subject.name
	msg := "name is missing"
}

